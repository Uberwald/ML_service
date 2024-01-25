import os
from ml.preprocess_data import process_csv
from database.database import SessionLocal, Model, create_model, get_model, User, Transaction
from cachetools import TTLCache
from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Path, APIRouter
from jose import JWTError, jwt
import bcrypt
from fastapi.responses import StreamingResponse
import io
import csv

app = FastAPI()
router = APIRouter()
# uvicorn main:app --reload
#streamlit run app.py
# Глобальная переменная для хранения информации о загруженном файле
uploaded_file_path = None
selected_model_info = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Конфигурация для хранения паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
token_cache = TTLCache(maxsize=100, ttl=3600)  # Например, токены будут храниться в течение 1 часа


# Зависимость для проверки наличия токена
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Необходима авторизация",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_status: str = payload.get("status", "user")  # Используем значение по умолчанию "user"
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"user_mail": username, "status": user_status}


def hash_password(password: str) -> str:
    # Генерация соли и хэширование пароля
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


# Функция для создания и подписи токена
def create_access_token(data: dict):
    to_encode = data.copy()
    token = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return token


def is_admin(current_user: dict = Depends(get_current_user)):
    if current_user["status"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен. Требуется статус 'admin'",
        )
    return current_user


def is_admin_or_user(current_user: dict = Depends(get_current_user)):
    allowed_statuses = ["admin", "user"]

    if current_user["status"] not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен. Требуется статус 'admin' или 'user'",
        )
    return current_user


@app.post("/register/")
def register_user(email: str, password: str, status: str, db: Session = Depends(get_db)):
    # Проверяем, существует ли пользователь с таким email
    existing_user = db.query(User).filter(User.user_mail == email).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Пользователь с таким email уже зарегистрирован"
        )

    # Хэшируем пароль
    hashed_password = hash_password(password)

    # Определяем начальный баланс в зависимости от статуса
    if status not in ['user', 'admin']:
        raise HTTPException(
            status_code=400,
            detail="Недопустимый статус. Используйте 'user' или 'admin'"
        )

    # Определяем начальный баланс в зависимости от статуса
    balance = 300.0 if status == "user" else 9999999.0

    # Создаем нового пользователя
    new_user = User(user_mail=email, password_hash=hashed_password, balance=balance, status=status)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"user_id": new_user.user_id, "user_mail": new_user.user_mail, "status": new_user.status,
            "balance": new_user.balance}


@app.delete("/users/")
def delete_user_by_email(email: str, db: Session = Depends(get_db), current_user: dict = Depends(is_admin)):
    # Получаем пользователя из базы данных по email
    user = db.query(User).filter(User.user_mail == email).first()

    # Проверяем, существует ли пользователь с указанным email
    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден"
        )

    # Удаляем пользователя из базы данных
    db.delete(user)
    db.commit()

    return {"status": "Пользователь успешно удален", "user_email": email}


@app.post("/token/")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = db.query(User).filter(User.user_mail == form_data.username).first()

    if not user or not pwd_context.verify(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверные учетные данные",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Проверка, есть ли токен в кэше
    cached_token = token_cache.get(user.user_mail)
    if cached_token:
        return {"access_token": cached_token, "token_type": "bearer"}

    # Генерация токена
    access_token = create_access_token(data={"sub": user.user_mail, "status": user.status})

    # Сохранение токена в кэше
    token_cache[user.user_mail] = access_token

    return {"access_token": access_token, "token_type": "bearer"}


# Загрузка файла
@app.post("/uploadfile/")
async def create_upload_file(
        file: UploadFile = File(...),
        current_user: dict = Depends(is_admin_or_user)
):
    global uploaded_file_path
    # Сохраняем загруженный файл
    with open(file.filename, "wb") as f:
        f.write(file.file.read())

    # Сохраняем путь к загруженному файлу в глобальной переменной
    uploaded_file_path = file.filename

    # Возвращаем информацию о загруженном файле
    return {"filename": file.filename, "status": "File uploaded successfully"}


# Эндпоинт для отображения всех моделей в таблице
@app.get("/models/")
def get_all_models(db: Session = Depends(get_db)):
    models = db.query(Model).all()
    return {
        "models": [
            {
                "model_id": model.model_id,
                "model_name": model.model_name,
                "coin_price": int(model.coin_price),
                "file_name": model.file_name  # Include the file_name field
            }
            for model in models
        ]
    }


# Эндпоинт для выбора модели по её идентификатору
@app.put("/select_model/{model_id}/")
def select_model(
        model_id: int = Path(..., title="Идентификатор модели"),
        db: Session = Depends(get_db),
        current_user: dict = Depends(is_admin_or_user)
):
    global selected_model_info, model_path
    current_script_path = os.path.abspath(__file__)
    models_folder_path = os.path.join(os.path.dirname(current_script_path), "ml", "models")
    model = get_model(db, model_id)

    if model is None:
        raise HTTPException(status_code=404, detail="Модели с таким id не существует")

    selected_model_info = {"model_id": model_id, "model_name": model.model_name}

    model_file_path = os.path.join(models_folder_path, model.file_name)
    if not os.path.exists(model_file_path):
        raise HTTPException(status_code=404,
                            detail=f"Модель с названием {model.file_name} отсутствует в папке ml/models")

    model_path = model_file_path

    return {"model_id": model_id, "model_name": model.model_name, "model_path": model_file_path}


# Применение функции process_csv
@app.post("/processcsv/")
async def process_csv_endpoint(current_user: dict = Depends(is_admin_or_user), db: Session = Depends(get_db)):
    global uploaded_file_path, model_path, selected_model_info

    # Проверяем наличие загруженного файла и выбранной модели
    if not uploaded_file_path or not selected_model_info:
        raise HTTPException(status_code=400, detail="Загрузите файл и выберите модель")

    user = db.query(User).filter(User.user_mail == current_user["user_mail"]).first()
    if user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    model = db.query(Model).filter(Model.model_id == selected_model_info["model_id"]).first()
    if model is None:
        raise HTTPException(status_code=404, detail="Модель не найдена")

    if user.balance < model.coin_price:
        raise HTTPException(status_code=400, detail="Недостаточно средств")

    # Вычитаем стоимость модели из баланса пользователя
    user.balance -= model.coin_price

    # Создаём запись транзакции
    transaction = Transaction(
        user_mail=user.user_mail,
        model_id=model.model_id,
        transaction_type="prediction",
        amount=model.coin_price,
        details=f"Prediction using model {model.model_name}"
    )
    db.add(transaction)
    db.commit()

    try:
        # Попытка вызова функции process_csv
        processed_data = process_csv(uploaded_file_path, model_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Преобразуем массив NumPy в список словарей с числовыми ключами
    processed_data_list = processed_data.tolist()
    processed_data_dict = {i + 1: item for i, item in enumerate(processed_data_list)}

    # Создание CSV-файла в памяти
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Row', 'Prediction'])
    for key, value in processed_data_dict.items():
        writer.writerow([key, value])
    output.seek(0)  # Переместим указатель в начало файла

    # Удаляем скачанный файл после обработки
    os.remove(uploaded_file_path)

    # Сбрасываем глобальные переменные после обработки
    uploaded_file_path = None
    selected_model_info = None

    # Возвращаем результат обработки
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv",
                             headers={"Content-Disposition": "attachment;filename=processed_data.csv"})


@app.get("/check_status/")
def check_user_status(current_user: dict = Depends(get_current_user)):
    return {"status": current_user["status"]}


# Эндпоинт для создания новой модели
@app.post("/models/")
def create_model_endpoint(
        model_name: str,
        coin_price: float,
        file_name: str,
        db: Session = Depends(get_db),
        current_user: dict = Depends(is_admin)
):
    existing_model_name = db.query(Model).filter(Model.model_name == model_name).first()
    if existing_model_name:
        raise HTTPException(status_code=400, detail="Модель с таким именем уже существует")

    existing_file_name = db.query(Model).filter(Model.file_name == file_name).first()
    if existing_file_name:
        raise HTTPException(status_code=400, detail="Файл такой модели уже загружен")

    return create_model(db=db, model_name=model_name, coin_price=coin_price, file_name=file_name)


# Эндпоинт для удаления модели по её идентификатору
@app.delete("/models/{model_id}/")
def delete_model(
        model_id: int,
        db: Session = Depends(get_db),
        current_user: dict = Depends(is_admin)
):
    # Получаем модель из базы данных
    model = get_model(db, model_id)

    # Проверяем, существует ли модель с указанным идентификатором
    if model is None:
        raise HTTPException(status_code=404, detail="Модель не найдена")

    # Удаляем модель из базы данных
    db.delete(model)
    db.commit()

    return {"status": "Модель успешно удалена", "model_id": model_id}


@app.get("/get_all_users")
def get_all_users(db: Session = Depends(get_db), current_user: dict = Depends(is_admin)):
    users = db.query(User).all()
    return users


@app.get("/transactions/")
async def read_transactions(
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: dict = Depends(is_admin)
):
    transactions = db.query(Transaction).offset(skip).limit(limit).all()  # Используем пагинацию
    return transactions


@app.post("/recharge/")
async def recharge_balance(
        user_mail: str,
        amount: float,
        db: Session = Depends(get_db),
        current_user: dict = Depends(is_admin)
):
    try:
        # Найти пользователя по email
        user = db.query(User).filter(User.user_mail == user_mail).one()
    except NoResultFound:
        raise HTTPException(status_code=404, detail="User not found")

    # Пополнить баланс пользователя
    user.balance += amount

    # Создать транзакцию
    transaction = Transaction(
        user_mail=user_mail,
        transaction_type="recharge",
        amount=amount,
        details=f"Balance recharge of {amount}"
    )
    db.add(transaction)

    # Сохранить изменения в базе данных
    db.commit()

    return {"message": "Balance recharged successfully"}


@app.get("/current_user/")
async def read_current_user(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_mail = current_user["user_mail"]

    user = db.query(User).filter(User.user_mail == user_mail).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "user_mail": user.user_mail,
        "balance": user.balance,
        "status": user.status
    }
