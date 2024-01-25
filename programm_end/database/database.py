from sqlalchemy import create_engine, Column, Integer, String, Float, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import DateTime, ForeignKey

# Создаем подключение к базе данных SQLite
DATABASE_URL = "sqlite:///C:/Archive/Projects/ML_service/programm/database/test.db"
engine = create_engine(DATABASE_URL)

# Создаем сессию базы данных
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Создаем базовую модель для таблиц
Base = declarative_base()


# Определяем модель данных для таблицы "models"
class Model(Base):
    __tablename__ = "models"

    model_id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String, index=True)
    coin_price = Column(Float)
    file_name = Column(String, index=True)


# Определяем модель данных для таблицы "users"
class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    user_mail = Column(String, index=True)
    password_hash = Column(String)
    balance = Column(Float)
    status = Column(String, index=True)


class Transaction(Base):
    __tablename__ = "transactions"
    transaction_id = Column(Integer, primary_key=True, index=True)
    user_mail = Column(String, ForeignKey('users.user_mail'))
    model_id = Column(Integer, ForeignKey('models.model_id'))
    transaction_type = Column(String, index=True)
    amount = Column(Float)
    timestamp = Column(DateTime, default=func.now())
    details = Column(String)

    # Отношения
    user = relationship("User", backref="transactions")
    model = relationship("Model", backref="transactions")


Base.metadata.create_all(bind=engine)


# Методы для работы с таблицей "models"
def create_model(db, model_name, coin_price, file_name):
    db_model = Model(model_name=model_name, coin_price=coin_price, file_name=file_name)
    db.add(db_model)
    db.commit()
    db.refresh(db_model)
    return db_model


def get_model(db, model_id):
    return db.query(Model).filter(Model.model_id == model_id).first()
