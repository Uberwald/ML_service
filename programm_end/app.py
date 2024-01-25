import jwt
import requests
import streamlit as st
import pandas as pd
from database.database import User, Transaction, SessionLocal  # Импортируйте нужные классы и функции
from main import get_db
from sqlalchemy.exc import NoResultFound

API_URL = "http://127.0.0.1:8000"  # Замените на URL вашего сервера FastAPI

def login_user(email, password):
    """Вход в систему."""
    response = requests.post(f"{API_URL}/token", data={"username": email, "password": password})
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        raise Exception("Ошибка входа")

def register_user(email, password, status):
    """Регистрация пользователя."""
    response = requests.post(f"{API_URL}/register/", json={"email": email, "password": password, "status": status})
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Ошибка регистрации")

def upload_file(file, token):
    """Загрузка файла на сервер."""
    headers = {"Authorization": f"Bearer {token}"}
    files = {"file": file.getvalue()}
    response = requests.post(f"{API_URL}/uploadfile/", files=files, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Ошибка при загрузке файла")

def get_all_models(token):
    """Получение списка моделей."""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{API_URL}/models/", headers=headers)
    if response.status_code == 200:
        return response.json()['models']
    else:
        raise Exception("Ошибка получения данных")


def select_model_in_streamlit(model_id, token):
    url = f"http://localhost:8000/select_model/{model_id}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.put(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Ошибка при выборе модели: {response.text}")


def process_csv_in_streamlit(token):
    url = "http://localhost:8000/processcsv/"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(url, headers=headers)
    if response.status_code == 200:
        return response.content  # Возвращает содержимое файла CSV
    else:
        raise Exception(f"Ошибка при обработке файла: {response.text}")


def check_user_status(token):
    """Проверка статуса пользователя."""
    headers = {"Authorization": f"Bearer {token}"}
    url = "http://localhost:8000/check_status/"  # Правильный URL вашего API
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get("status")
    except Exception as e:
        st.error(f"Ошибка при запросе статуса: {e}")
        return None

def get_all_users(token):
    """Запрос списка всех пользователей с сервера."""
    headers = {"Authorization": f"Bearer {token}"}
    url = "http://localhost:8000/get_all_users"  # Правильный URL вашего API
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Ошибка при запросе списка пользователей: {e}")
        return None

def get_transactions(token, skip, limit):
    """Получение списка транзакций."""
    url = "http://localhost:8000/transactions/"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"skip": skip, "limit": limit}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Ошибка при получении транзакций: {e}")
        return []

def recharge_balance(user_mail, amount, db_session):
    try:
        user = db_session.query(User).filter(User.user_mail == user_mail).one()
    except NoResultFound:
        return "Пользователь не найден"

    user.balance += amount

    transaction = Transaction(
        user_mail=user_mail,
        transaction_type="recharge",
        amount=amount,
        details=f"Balance recharge of {amount}"
    )
    db_session.add(transaction)
    db_session.commit()

    return "Баланс успешно пополнен"



def app():
    st.title("Система входа, регистрации и загрузки файла")

    if 'token' not in st.session_state:
        with st.form("login"):
            st.write("Вход")
            login_email = st.text_input("Email", key="login_email")
            login_password = st.text_input("Пароль", type="password", key="login_password")
            submit_login = st.form_submit_button("Войти")

            if submit_login:
                try:
                    token = login_user(login_email, login_password)
                    st.session_state['token'] = token
                    st.success("Вход выполнен успешно")
                except Exception as e:
                    st.error(str(e))

        with st.form("register"):
            st.write("Регистрация")
            reg_email = st.text_input("Email", key="reg_email")
            reg_password = st.text_input("Пароль", type="password", key="reg_password")
            reg_status = st.selectbox("Статус", ["user", "admin"], key="reg_status")
            submit_reg = st.form_submit_button("Зарегистрироваться")

            if submit_reg:
                try:
                    response = register_user(reg_email, reg_password, reg_status)
                    st.success("Регистрация выполнена успешно")
                    st.json(response)
                except Exception as e:
                    st.error(str(e))

    if 'token' in st.session_state:
        st.write("Загрузка файла")
        uploaded_file = st.file_uploader("Выберите файл")
        if uploaded_file is not None:
            try:
                response = upload_file(uploaded_file, st.session_state['token'])
                st.success("Файл успешно загружен")
            except Exception as e:
                st.error(str(e))
        st.write("Список моделей:")
        try:
            models = get_all_models(st.session_state['token'])
            st.table(models)
        except Exception as e:
            st.error(f"Ошибка при получении данных: {e}")

        try:
            models = get_all_models(st.session_state['token'])
            model_options = {model["model_name"]: model["model_id"] for model in models}
            selected_model_name = st.selectbox("Выберите модель", options=list(model_options.keys()))

            if st.button("Выбрать модель"):
                model_id = model_options[selected_model_name]
                try:
                    response = select_model_in_streamlit(model_id, st.session_state['token'])
                    st.success("Модель выбрана успешно")
                    # Здесь можно обработать ответ от сервера
                except Exception as e:
                    st.error(str(e))
        except Exception as e:
            st.error(f"Ошибка при получении списка моделей: {e}")

        if st.button("Обработать файл"):
            with st.spinner("Обработка файла... Пожалуйста, подождите"):
                try:
                    csv_data = process_csv_in_streamlit(st.session_state['token'])
                    st.download_button(label="Скачать обработанный файл",
                                       data=csv_data,
                                       file_name="processed_data.csv",
                                       mime="text/csv")
                except Exception as e:
                    st.error(str(e))

        user_status = check_user_status(st.session_state['token'])

        if user_status == "admin":
            st.header("Настройки системы:")
            if st.button('Показать пользователей'):
                users = get_all_users(st.session_state['token'])
                if users is not None:
                    df = pd.DataFrame(users)
                    st.table(df)
            st.write("Таблица транзакций")
            skip = st.number_input("Min", min_value=0, value=0, step=10)
            limit = st.number_input("Max", min_value=1, value=10, step=10)
            if st.button("Загрузить транзакции"):
                transactions = get_transactions(st.session_state['token'], skip, limit)
                if transactions:
                    df_transactions = pd.DataFrame(transactions)
                    st.table(df_transactions)

            with st.form("recharge_form"):
                user_mail = st.text_input("Email пользователя")
                amount = st.number_input("Сумма", min_value=0.0, format="%.2f")
                submit_button = st.form_submit_button("Пополнить")

            if submit_button:
                # Создаем сессию базы данных
                db_session = SessionLocal()
                try:
                    result = recharge_balance(user_mail, amount, db_session)
                    if result == "Пользователь не найден":
                        st.error(result)
                    else:
                        st.success(result)
                finally:
                    # Важно закрыть сессию после использования
                    db_session.close()



if __name__ == "__main__":
    app()
