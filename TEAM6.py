from flask import Flask,request,render_template,flash,redirect,url_for,session
import sqlite3
import bcrypt
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

#-----------------------------------------------------------------------------------------------------
                                 #hashing
def secure_password(password):
    min_l=8
    if len(password)<min_l:
        return False
    elif not any(char.isupper()for char in password):
        return False
    elif not any(char.islower()for char in password):
        return False
    elif not any(char.isdigit()for char in password):
        return False
    elif not re.search(r"[!@#$%^&*()?.,:\"{}<>|]",password):
        return False
    else:
      return True 
    

def hash_password(password):
    salt=bcrypt.gensalt()
    hashed_password=bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

def compare_password(new_password,hashed_password):
    return bcrypt.checkpw(new_password.encode(),hashed_password.encode())

ALLOWED_EXTENTIONS={'png','jpg','gif','jpeg'}
MAX_FILE_SIZED_BYTES=10*1024*1024

hashed_adminpassword=hash_password('Ra7eeq@Banan3')

#-----------------------------------------------------------------------------------------------------
                                   #db
#---------------------------------------------------movies-----------------------------------------
def files_areallowed(filename):
    return'.'in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENTIONS

def file_size_isallowed(file):
    original_position=file.tell()
    file.seek(0,os.SEEK_END)
    file_size=file.tell()
    file.seek(original_position)
    return file_size<= MAX_FILE_SIZED_BYTES   
  

def init_movies_table():
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS movies(
                   id INTEGER PRIMARY KEY AUTOINCREMENT, 
                   user_id INTEGER NOT NULL, 
                   movie_name TEXT NOT NULL, 
                   description TEXT,
                   ticket_price REAL NOT NULL,
                   movie_type TEXT NOT NULL,
                   image_url TEXT,
                   counter_is_sold INTEGER DEFAULT 0,
                   FOREIGN KEY (user_id) REFERENCES user (id)
                   ) ''')
    connection.commit()

def add_new_movie(user_id,movie_name,description,ticket_price,movie_type,image_url=None,counter_is_sold=0):
    connection=sqlite3.connect('database.db')
    cursor =connection.cursor()
    query =f'''INSERT INTO movies(user_id,movie_name,description,ticket_price,movie_type,image_url,counter_is_sold) VALUES(?,?,?,?,?,?,?)'''
    cursor.execute(query,(user_id,movie_name,description,ticket_price,movie_type,image_url,counter_is_sold))
    connection.commit()    

def get_movie(id):
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    query=f'''SELECT*FROM movies WHERE id=?'''
    cursor.execute(query,(id,))
    return cursor.fetchone()

def get_movie_by_user_id(user_id):
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    query=f'''SELECT*FROM movies WHERE user_id=?'''
    cursor.execute(query,(user_id,))
    return cursor.fetchone()

def get_allmovies():
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    query=f'''SELECT*FROM movies'''
    cursor.execute(query)
    return cursor.fetchall()

def get_allmovie_whit_type(movie_type):
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    query=f'''SELECT*FROM movies WHERE movie_type=? '''
    cursor.execute(query,(movie_type,))
    return cursor.fetchall()


def check_num_of_buying(movie_id):
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    query='''SELECT (counter_is_sold ) FROM movies  WHERE id =? '''
    cursor.execute(query,(movie_id,))
    return cursor.fetchone()[0]


def increment_counter(movie_id):
    connection=sqlite3.connect('database.db')
    cursor = connection.cursor()
    update_query = ('''UPDATE movies SET counter_is_sold=counter_is_sold + 1 WHERE id = ?''')
    cursor.execute(update_query, (movie_id,))
    connection.commit()

def update_profit(movie_price,user_id):
        connection=sqlite3.connect('database.db')
        cursor=connection.cursor()
        # Update owner's balance
        update_balance_query = '''UPDATE user SET profit = profit + ? WHERE id = ?'''
        cursor.execute(update_balance_query, (movie_price, user_id))
        connection.commit()


#-----------------------------------------user-------------------------------------------------------
def intia_user_table ():
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE, 
                    password TEXT NOT NULL, 
                    admin BOOLEN DEFAULT 0,
                    profit INTEGER DEFAULT 0)
                   ''')
    connection.commit()

def add_user(username,password,admin=0,profit=0):
    connection=sqlite3.connect('database.db')
    cursor =connection.cursor()
    hashed_password=hash_password(password)
    query = '''INSERT INTO user(username,password ,admin,profit) VALUES(?,?,?,?)'''
    cursor.execute(query,(username,hashed_password,admin,profit))
    connection.commit()

def check_username(username): # get user
    connection=sqlite3.connect('database.db')
    cursor=connection.cursor()
    query='''SELECT*FROM user WHERE username=?'''
    cursor.execute(query,(username,))
    return cursor.fetchone()
#---------------------------------------------------------comments-------------------------------------
def init_comments_table():
    connection=sqlite3.connect('database.db')
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, 
            movie_id INTEGER NOT NULL, 
            comment TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user (id), 
            FOREIGN KEY (movie_id) REFERENCES movies (id) )
    ''')
    connection.commit()
    
def add_new_Comment( user_id, movie_id,comment):
    connection=sqlite3.connect('database.db')
    cursor = connection.cursor()
    query = '''INSERT INTO comments (user_id,movie_id,comment) VALUES (?,?,?)'''
    cursor.execute(query, (user_id, movie_id, comment))
    connection.commit()

def GetCommentsFormovie( movie_id):
    connection=sqlite3.connect('database.db')
    cursor = connection.cursor()
    query = '''
        SELECT  user.username, comments.comment, comments.timestamp 
        FROM comments 
        JOIN user ON comments.user_id = user.id
        WHERE comments.movie_id = ? 
    '''
    #we execute these things that have ? or we type them
    cursor.execute(query, (movie_id,)) 
    return cursor.fetchall()



#-----------------------------------------------------------------------------------------------------

app=Flask (__name__)
app.secret_key="nzwudh827351`r#467&';,"
limiter=Limiter(app=app,key_func=get_remote_address,default_limits=["30 per minute"])

#-----------------------------------------------------------------------------------------------------
                                       #register

@app.route('/register', methods=["GET","POST"])
def register():
    if request.method=="POST":
        username=request.form["username"]
        password=request.form["password"]
        if not secure_password(password):
            flash("password is not secure enogh","danger")
            return render_template("register.html")
        check_iffound=check_username(username) #get user
        if check_iffound:
            flash("the user is already found","danger")
            return render_template("register.html")
        else:
            is_admin=compare_password(password,hashed_adminpassword)
            if is_admin:
                add_user(username,password,is_admin)
                flash("admin created succesully","success")
                return redirect(url_for("login"))
            add_user(username,password)
            flash("user created succesully","success")
            return redirect(url_for("login"))
    return render_template("register.html")

#-----------------------------------------------------------------------------------------------------
                                              #login

@app.route('/login',methods=["GET","POST"])
@limiter.limit("7 per minute")
def login():
    if request.method=="POST":
        username=request.form["username"]
        password=request.form["password"]
        check_iffound_inthetable=check_username(username)
        if check_iffound_inthetable:
           itisnot= compare_password(password,check_iffound_inthetable[2])
           if itisnot:
             session['username']= check_iffound_inthetable[1]
             session['user_id']=check_iffound_inthetable[0] 
             if check_iffound_inthetable[3]:
                 session['admin']=check_iffound_inthetable[3]
                 flash("login succesfully","success")
                 return redirect(url_for("perfect"))
             flash("login succesfully","success")
             return redirect(url_for("perfect"))
           flash("incorrect username or passowrd","dager")
           return render_template("login.html")
     
        else:
            flash("incorrect username or password","danger")
            return render_template("login.html")
    return render_template("login.html")    
 

@app.route('/')
def perfect():
    if 'username' in session:
        return render_template("index.html",movies=get_allmovies())
    
    return "you are not login" 

@app.route('/cinema/<movie_type>')
def cinema(movie_type):
 if 'username' in session:
  return render_template("index.html",movies=get_allmovie_whit_type(movie_type))
 flash("you are not loged in","danger")


#-----------------------------------------------------------------------------------------------------
                                            #uploading movie

@app.route('/upload/<user_name>', methods=["GET","POST"])
def uploadGadget(user_name): 
     if user_name != session['username']:
         flash("can not reach this page","danger")
         return redirect(url_for("perfect")) 
     user=check_username(user_name)
     if not user[3]: #admin
        flash("can not reach this page","danger")
        return redirect(url_for("perfect"))  
     if not 'admin' in session:
        flash("you are not loged in","danger")
        return render_template("login.html") 
     if request.method=="POST":
        gdimage=request.files['image']
        if gdimage.filename=='':
            flash("image is required","danger")
            return render_template("upload_movie.html",user=user)
        if not gdimage or not files_areallowed(gdimage.filename)or not file_size_isallowed(gdimage):
            flash("invalid file to upload","danger")
            return render_template("upload-movie.html",user=user)
        movie_name=request.form['movie_name']
        description=request.form['description']
        ticket_price=request.form['ticket_price']
        movie_type=request.form['movie_type']
        image_url=f"uploads/{gdimage.filename}"
        gdimage.save("Static/"+ image_url)
        user_id=user[0]
        add_new_movie(user_id,movie_name,description,ticket_price,movie_type,image_url)
        
        return redirect(url_for("perfect"))
     return render_template("upload-movie.html", user=user)

#-----------------------------------------------------------------------------------------------------
                                        #movie and comments

@app.route('/<movie_id>')
def get_Specific_movie(movie_id):
	# gets info from db 
	movie = get_movie(movie_id)
	comments = GetCommentsFormovie( movie[0])  
	return render_template("movie.html", movie=movie, comments=comments)



@app.route('/add-comment/<movie_id>', methods=['POST'])
def addComment(movie_id):
	comment = request.form['comment']
	user_id = session['user_id']
	add_new_Comment(user_id,movie_id,comment)
	return redirect(url_for("get_Specific_movie", movie_id=movie_id))


#-----------------------------------------------------------------------------------------------
                                       #Buy a ticket 
                                
@app.route('/buy-ticket/<movie_id>',methods=['POST','GET'])
def buyTicket(movie_id):
    movie = get_movie(movie_id)
    count = check_num_of_buying(movie_id)
    if movie:
     if count <=5:
            
            flash(f"Congratulations You have bought a ticket","success")
            increment_counter(movie_id)
            update_profit(movie[4],movie[1])
            return redirect(url_for("get_Specific_movie", movie_id=movie_id))
       
     else:
        flash("Sorry no more tickets are available", "danger")
        return redirect(url_for('get_Specific_movie', movie_id=movie_id))
    flash("this movie is not exists","danger")
    return redirect(url_for('perfect'))


#----------------------------------------------------------------------------------------------
                                          #account
@app.route('/profit/<user_name>')
def profit(user_name):
     if user_name != session['username']:
         flash("can not reach this page","danger")
         return redirect(url_for("perfect")) 
     user=check_username(user_name)
     if not user[3]: #admin
        flash("can not reach this page","danger")
        return redirect(url_for("perfect"))  
     if not 'admin' in session:
       flash("You are Not Logged In", "danger")
       return redirect(url_for("login"))
     return render_template("profile.html",users=check_username(user_name),user=user)

#----------------------------------------------------------------------------------------------
                                          #withdrawing

@app.route('/withdraw/<user_name>')
def withdraw(user_name):
 if user_name != session['username']:
         flash("can not reach this page","danger")
         return redirect(url_for("perfect")) 
 user=check_username(user_name)
 if not user[3]: #admin
        flash("can not reach this page","danger")
        return redirect(url_for("perfect"))  
 if not 'admin' in session:
    flash("You are Not Logged In", "danger")
    return redirect(url_for("login"))
 return render_template("withdraw.html", users=check_username(user[0]),user=user)
	

#-----------------------------------------------------------------------------------------------
                                       #logout

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('perfect'))






#-----------------------------------------------------------------------------------------------------

if __name__ =='__main__':
    intia_user_table()
    init_movies_table()
    init_comments_table()
    app.run(debug=True)