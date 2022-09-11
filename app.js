//jshint esversion:6
require("dotenv").config();
const express = require("express")
const ejs = require("ejs")
const bodyParser = require("body-parser")
const mongoose = require("mongoose");
// const encrypt=require("mongoose-encryption");  environment variables(.env file) is used in this method
// const md5=require("md5");
// const bcrypt=require("bcrypt");
// const saltRound=15; // now we are using passport for authentication, session and cookies not using bcrypt and salt explicitly

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate=require("mongoose-findorcreate");
const app = express();

app.use(express.static("public"))
app.set("view engine", "ejs")
app.use(bodyParser.urlencoded({
  extended: true
}))

app.use(session({
  secret: "our little secret",
  resave: false,
  saveUninitialized: false
}))


app.use(passport.initialize()); // initialized the passport
app.use(passport.session()); //use passport to manage session

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    UserProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"   // posted by a person on stackoverflow
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId:String,
  secret:String
})

userSchema.plugin(passportLocalMongoose); // using passport-local-mongoose package to hash and salt password and save it to our db
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]}); // we have used hash function so we dont need it
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// a simple way to serialize and deserealize user for local strategy
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// we need to use a way which works for all Strategy
passport.serializeUser(function(user,done){
  done(null,user.id);
});
passport.deserializeUser(function(id,done){
  User.findById(id,function(err,user){
    done(err,user);
  })
})

app.get("/", function(req, res) {
  res.render("home");
})
app.get("/login", function(req, res) {
  res.render("login")
})
app.get("/register", function(req, res) {
  res.render("register")
});
app.get("/secrets",function(req,res) {
  // we dont need authentication in secrets page anybody can see secrets

  // we are finding all the docs which has secret field not equal to null and render it
  User.find({"secret":{$ne:null}},function(err,foundUsers){
    if(err)
    console.log(err);
    else
    {
      if(foundUsers)
      res.render("secrets",{userWithSecrets:foundUsers});
    }
  })
})

app.get("/logout", function(req, res) {
  req.logout(function(err)
{
  if(!err)
  res.redirect("/");
});
})
app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: "/login "}),
    function(req, res) {
      // Successful authentication, redirect to page secrets.
      res.redirect("/secrets");
    });

    app.get("/submit",function(req,res){
      if(req.isAuthenticated())
      res.render("submit");
      else
        res.redirect("/login");
    })

// for register page
app.post("/register", function(req, res) {
  User.register({
      username: req.body.username
    },
    req.body.password,
    function(err, user) {
      if (err)
        console.log(err);
      else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        })
      }
    }
  )

})

// login page
app.post("/login", function(req, res) {

  const user = new User({   // created a new user
    username: req.body.username,
    password: req.body.password
  })
 // passing the user obj/credentials to login method
  req.login(user, function(err) {
      if (err)
        console.log(err);
      else {
        passport.authenticate("local")(req, res, function() { // authenticate if user ss legit
          res.redirect("secrets");
        })

    }
  })

})

app.post("/submit",function(req,res){
  const submittedSecret=req.body.secret;

  User.findById(req.user.id,function(err,foundUser){
    if(err)
    console.log(err);
    else
    {
      if(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  })
})
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started Successfully");
});
