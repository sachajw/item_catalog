from datetime import datetime
from project import db, bcrypt  # app/__inti__.py
from flask_login import UserMixin
from project import login_manager
from flask_login import LoginManager


class User(UserMixin, Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    user_name = Column(String(20))
    user_email = Column(String(60), unique=True, index=True)
    user_password = Column(String(80))
    registration_date = Column(String(20), nullable=False, default=datetime.utcnow)

def check_password(self, password):
        return bcrypt.check_password_hash(self.user_password, password)

@classmethod
def create_user(cls, user, email, password):
        user = cls(user_name=user,
                   user_email=email,
                   user_password=bcrypt.generate_password_hash('password').decode('utf-8')
        session.add(user)
        session.commit()
        return user


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
