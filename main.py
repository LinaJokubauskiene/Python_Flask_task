import os
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user
from flask_bcrypt import Bcrypt


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)


app.config['SECRET_KEY'] = "?``§=)()%``ÄLÖkhKLWDO=?)(_:;LKADHJATZQERZRuzeru3rkjsdfLJFÖSJ"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'my_database.db?check_same_thread=False')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
db.init_app(app)


login_manager = LoginManager(app)
login_manager.login_view = 'Login'
login_manager.login_message_category = 'info'
bcrypt = Bcrypt(app)

migrate = Migrate(app, db)

association_table = db.Table('association_table', db.metadata,
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column("Full name", db.String, unique=True, nullable=False)
    email = db.Column("Email", db.String, unique=True, nullable=False)
    password = db.Column("Password", db.String, nullable=False)
    groups = db.relationship("Group", secondary=association_table, back_populates="users")
    # bills = db.relationship("Bill", back_populates="groups")


class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column("Group name", db.String, unique=True, nullable=False)
    description = db.Column('Description', db.String, unique=True, nullable=False)
    bills = db.relationship("Bill", back_populates="groups")
    users = db.relationship("User", secondary=association_table, back_populates="groups")


class Bill(db.Model):
    __tablename__ = 'bill'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column("Name", db.String, unique=True, nullable=False)
    sum = db.Column("Sum", db.Integer)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    groups = db.relationship("Group", back_populates="bills")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    import forms

    db.create_all()

@app.route('/')
def index():
    return render_template('base.html')


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('sign_in'))
    form = forms.SignUpForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Registration succeeded, {user.username}, now you can sign in.', 'success')
        return redirect(url_for('add_user'))
    return render_template('sign_up.html', title='Register', form=form)


@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if current_user.is_authenticated:
        return redirect(url_for('sign_in'))
    form = forms.SignInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash(f'User does not exist!')
            return redirect(url_for('sign_up'))
        if not bcrypt.check_password_hash(User.password, form.password.data):
            flash(f'User / password do not match!', 'check password')
            return redirect(url_for('sign_up'))
        login_user(user)
        flash(f'Welcome!')
        return redirect(url_for('show_groups'))
    return render_template('sign_in.html', form=form)

@app.route("/add_user", methods=["GET", "POST"])
def add_user():
    db.create_all()
    form = forms.UserForm()
    if form.validate_on_submit():
        added_user = User(username=form.username.data, user_id=form.user.data.id)
        for group in form.group.data:
            assigned_group = Group.query.get(group.id)
            added_user.append(assigned_group)
        db.session.add(add_bill)
        db.session.commit()
        return redirect(url_for('users'))
    return render_template("add_user.html", form=form)


@app.route('/sign_out')
def sign_out():
    flash(f'See you next time!')
    logout_user()
    return redirect(url_for('index'))

@app.route('/show_groups')
# @login_required
def show_groups():
    groups = Group.query.all()
    return render_template('show_groups.html', groups=groups)


@app.route('/show_bills')
def show_bills():
    bills = Bill.query.all()
    return render_template('show_bills.html', bills=bills)


@app.route("/add_group", methods=["GET", "POST"])
def add_group():
    db.create_all()
    form = forms.GroupForm()
    if form.validate_on_submit():
        add_group = Group(name=form.name.data, description=form.description.data)
        for user in form.users.data:
            added_user = User.query.get(user.id)
            add_group.users.append(added_user)
        db.session.add(add_group)
        db.session.commit()
        return redirect(url_for('groups'))
    return render_template("add_group.html", form=form)


@app.route("/add_bill", methods=["GET", "POST"])
def add_bill():
    db.create_all()
    form = forms.BillForm()
    if form.validate_on_submit():
        add_bill = Bill(name=form.name.data, sum=form.sum.data, user_id=form.user.data.id)
        db.session.add(add_bill)
        db.session.commit()
        return redirect(url_for('bills'))
    return render_template("add_bill.html", form=form)


if __name__ == '__main__':
    app.run(debug=True)
