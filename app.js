var express = require('express');
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy


var cookieParser = require('cookie-Parser');
var bodyParser = require('body-parser');
var session = require('express-session');
const bcrypt = require('bcryptjs');

//var pg = require('pg-promise');
var pgStore = require('connect-pg-simple');
const promise = require('bluebird');
var app = express();

const config = {
    host: 'localhost',
    port: 5432,
    database: 'passportClassdb',
    user: 'postgres'
};


// pg-promise initialization options:
const initOptions = {

    // Use a custom promise library, instead of the default ES6 Promise:
    promiseLib: promise,

    
};

// Load and initialize pg-promise:
const pgp = require('pg-promise')(initOptions);


// Create the database instance:
const db = pgp(config);


app.set('view engine', 'ejs');
app.set('views', './views');

//public folder
app.use(express.static('./public'));

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

//must add session information before adding passport, otherwise, won't work
app.use(cookieParser());

//store allows us to store session in the database. Must create a session table
// psql mydatabase < node_modules/connect-pg-simple/table.sql
// session information will be persisted and not destroyed
app.use(session({
    secret: 'mySecretSessionKey',
    resave: true,
    saveUninitialized: true,
    store: new (require('connect-pg-simple')(session))({conObject: config})

}));

//initialize passport
//Doc: In a Connect or Express-based application, 
//passport.initialize() middleware is required to initialize Passport. 
//If your application uses persistent login sessions, passport.session() 
//middleware must also be used.
app.use(passport.initialize());
app.use(passport.session());

//app.use(require('./routes/index'));

app.get('/login', function(req, res) {
 

    res.send(
        ` 
            <h1>Login</h1>
            <form action="/login" method="post">
                <div>
                    <label>Username:</label>
                    <input type="text" name="username"/>
                </div>
                <div>
                    <label>Password:</label>
                    <input type="password" name="password"/>
                </div>
                <div>
                    <input type="submit" value="Log In"/>
                </div>
            </form>
        `
    ); //end of res.send
    
});//end of app.get

app.post('/login',
  passport.authenticate('local', { successRedirect: '/dashboard',
                                   failureRedirect: '/login'})
);


app.get('/register', function(req, res) {
 

    res.send(
        ` 
        <h1>Registration</h1>

        <form action="/register" method="POST">
          <input type="text" name="username" />
          <input type="text" name="password" />
          <input type="submit" />
        </form>
        `
    ); //end of res.send
    
});//end of app.get

app.post('/register',function(req,res){

    let username = req.body.username;
    // hashing the password
    let password = bcrypt.hashSync(req.body.password,8);
  
    db.none('INSERT INTO users(username, password) VALUES($1, $2)', [username, password])
    .then(() => {
        // success;
        res.redirect('/login');
    })
    .catch(error => {
        // error;
    });
  
    //save to database
    
    
  });

  app.get('/logout', function(req, res, next){
    req.session.destroy((err) => {
        if(err) return next(err)

        req.logout()

        res.sendStatus(200)
    })
  })

  app.get('/dashboard',function(req,res){

    if(!req.isAuthenticated()) {
        res.redirect('/login');
      return
    }
  
    res.send("you've arrived here, so you must be authenticated")
  })


  passport.use(new LocalStrategy((username, password, done) => {
    db.any('SELECT * FROM users WHERE username=$1', [username]).then ((results) => {
        
        if(results != null) {
            const data = results[0]
            bcrypt.compare(password, data.password, function(err, res) {
                if(res) {
                    console.log("Hello world")
                    console.log(data)
                    done(null, { id: data.id, username: data.username})
                } else {
                    console.log("Returned nothing")
                    done(null, false)
                }
            })
        } else {
            console.log("just out there")
            done(null, false)
        }

        //done(null, data[0])

        //console.log(username)
    } //end of callback

    
)//end of then promise

    

    
}))

passport.serializeUser((user, done) => {
    done(null, user.id)
    
})

passport.deserializeUser((id, done) => {
    db.one('SELECT id, username FROM users WHERE id = $1', [parseInt(id, 10)]).then( (data) => {
        
       
        done(null, data)
    }//end of callback
    )//end of promise
    
})


var server = app.listen(2001, function(){
    console.log('Example app listening on port 2001 ');
});

