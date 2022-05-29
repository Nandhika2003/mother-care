import email
from unicodedata import name
from flask import Flask,render_template,request,flash,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,login_required,logout_user,current_user,LoginManager
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)
app.secret_key = "super secret key"

db_name="busy.db"

app.config['SQLALCHEMY_DATABASE_URI']=f"sqlite:///{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

db=SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(200),unique=True)
    password=db.Column(db.String(200))
    name=db.Column(db.String(200))
    questionnaire=db.relationship('Questionnaire')

class Questionnaire(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    q1=db.Column(db.Integer)
    q2=db.Column(db.Integer)
    q3=db.Column(db.Integer)
    q4=db.Column(db.Integer)
    q5=db.Column(db.Integer)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))

login_manager=LoginManager()
login_manager.login_view="login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route("/")
def hello_world():
    return render_template("index_home.html")

@app.route("/login",methods=["POST","GET"])
def login():
    if request.method=="POST":
        name=request.form['name']
        password=request.form['password']

        user=User.query.filter_by(name=name).first()
        if user:
            if check_password_hash(user.password,password):
                login_user(user,remember=True)
                return redirect("/dashboard")
            else:
                flash("Incorrect Password, Try Again",category='error')
        else:
            flash("Email does not exist.",category='error')
    return render_template('index_login.html',user=current_user)

@app.route("/signup",methods=['POST','GET'])
def signup():
    if request.method =="POST":
        name=request.form['name']
        email=request.form['email']
        password=request.form['password']
        if len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(name) < 2:
            flash('Name must be greater than 1 character.', category='error')
        elif len(password) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, name=name, password=generate_password_hash(
                password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            #login_user(new_user, remember=True)
            flash('Account created!', category='success')
            login_user(new_user,remember=True)
            #login_status=1
            return redirect("/dashboard")
    return render_template("index_signup.html")



@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("index_dashboard.html")

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/login")



if __name__=='__main__':
    app.run(debug=True)