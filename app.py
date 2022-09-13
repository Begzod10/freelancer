from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, Boolean, String
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.secret_key = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost:5432/freelancer'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

user_group = db.Table('user_group',
                      Column('user_id', Integer, db.ForeignKey('users.id')),
                      Column('group_id', Integer, db.ForeignKey('groups.id'))
                      )


class Users(db.Model):
    id = Column(Integer, primary_key=True)
    username = Column(String)
    job_id = Column(Integer, db.ForeignKey('jobs.id'))
    name = Column(String)
    password = Column(String)
    works = db.relationship('Works', backref='user_work_id')
    work_list = db.relationship('WorkList', backref="user_worklist_id")
    group = db.relationship('Groups', backref="user_id")
    group_of = db.relationship('Groups', secondary="user_group", backref="user_groupof_id")


class Works(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    status = Column(Boolean, default=False)
    given_by_id = Column(Integer)
    owner_id = Column(Integer, db.ForeignKey('users.id'))
    work = db.relationship('WorkList', backref="works_id")


class WorkList(db.Model):
    id = Column(Integer, primary_key=True)
    description = Column(String)
    status = Column(Boolean, default=False)
    given_by_id = Column(Integer)
    owner_id = Column(Integer, db.ForeignKey('users.id'))
    work_id = Column(Integer, db.ForeignKey('works.id'))


class Jobs(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    users = db.relationship('Users', backref="job")


class Groups(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String)
    owner_id = Column(Integer, db.ForeignKey('users.id'))


db.create_all()


def get_current_user():
    user_result = None
    if 'user' in session:
        user = session['user']
        user = Users.query.filter_by(username=user).first()
        user_result = user

    return user_result


@app.route('/')
def index():
    user = get_current_user()
    return render_template('index.html', user=user)


@app.route('/login', methods=['POST', 'GET'])
def login():
    user = get_current_user()
    if request.method == "POST":
        username = request.form.get('username').lower()
        password = request.form.get('password')
        username_sign = Users.query.filter_by(username=username).first()
        if username_sign and check_password_hash(username_sign.password, password):
            session['user'] = username_sign.username
            return redirect(url_for('index'))
        else:
            return redirect(url_for('register'))
    return render_template('login.html', user=user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    user = get_current_user()
    jobs = Jobs.query.order_by('id').all()
    if request.method == "POST":
        username = request.form.get('username').lower()
        if Users.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already exists!", jobs=jobs, user=user)
        name = request.form.get('name').lower()
        password = request.form.get('password')
        job = int(request.form.get('job'))
        hashed = generate_password_hash(password, method='sha256')
        add = Users(name=name, username=username, job_id=job, password=hashed)
        db.session.add(add)
        db.session.commit()
        session['user'] = name
        return redirect(url_for('index'))

    return render_template('register.html', jobs=jobs, user=user)


@app.route('/create_work', methods=['POST', 'GET'])
def create_work():
    user = get_current_user()
    users_list = Jobs.query.filter(Jobs.name != "admin", Jobs.name != "freelancer").all()
    works = Works.query.order_by('id').all()
    if request.method == "POST":
        work = request.form.get('work').lower()
        owner = int(request.form.get('owner'))
        if Works.query.filter_by(name=work, owner_id=owner).first():
            return render_template('work.html', user=user, users_list=users_list, error="Work is already given",
                                   works=works)

        add = Works(name=work, owner_id=owner, given_by_id=user.id)
        db.session.add(add)
        db.session.commit()
        return redirect(url_for('create_work'))
    return render_template('work.html', user=user, users_list=users_list,works=works)


@app.route('/users', methods=['POST', 'GET'])
def users():
    return render_template('user_list.html')


@app.route('/groups', methods=['POST', 'GET'])
def groups():
    return render_template('groups.html')


@app.route('/jobs', methods=['POST', 'GET'])
def jobs():
    user = get_current_user()
    if request.method == "POST":
        name = request.form.get('name')
        add = Jobs(name=name)
        db.session.add(add)
        db.session.commit()
        return redirect(url_for('jobs'))
    jobs = Jobs.query.order_by('id').all()

    return render_template('jobs.html', jobs=jobs, user=user)


@app.route('/change/<int:job_id>', methods=['POST'])
def change(job_id):
    Jobs.query.filter_by(id=job_id).update({'name': request.form.get("job")})
    db.session.commit()
    return redirect(url_for('jobs'))


@app.route('/delete_job/<int:job_id>')
def delete_job(job_id):
    Jobs.query.filter_by(id=job_id).delete()
    db.session.commit()
    return redirect(url_for('jobs'))


@app.route('/logout')
def logout():
    session['user'] = None
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
