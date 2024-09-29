const express = require("express");
const expressSession = require("express-session");
const flash = require("connect-flash");
const Router = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const cookieParser = require("cookie-parser");
const secretKey = process.env.authKey;
const userModel = require("./models/user");
const user = require("./models/user");
const PORT = 6969;


Router.use(expressSession({
    secret: "topsecret",
    saveUninitialized: false,
    resave: false
}));

Router.use(flash());


Router.use(express.json());
Router.use(express.urlencoded({ extended: true }));
Router.use(express.static(path.join(__dirname, "public")));
Router.use(cookieParser());
Router.set("view engine", "ejs");


// Routes

Router.get("/", (req, res) => {
    res.render("slash");
});
Router.get("/login", (req, res) => {
    res.render("login", { errorMessage: req.query.error });
});

Router.post("/logcheck", async (req, res) => {
    const { email, password } = req.body; 

    try {
        const user = await userModel.findOne({ email: req.body.email });
        if (!user) {
            return res.redirect("/login?error=User not found");
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.redirect("/login?error=Incorrect password");
        }
        let token = jwt.sign({email}, "${secretKey}");
        res.cookie("token", token)
        // Successful login, redirect to profile page
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
        res.redirect("/login?error=An error occurred");
    }

});

Router.get("/profile", async(req, res)=>{
    const { email, password, age, username } = user;
    res.render("profile", { email, password, age, username });

});

Router.get("/signup", async (req, res) => {
    res.render("signup")

});
Router.post("/create", (req, res) => {
    let { username, email, password, age } = req.body;

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, async (err, hash) => {
            let { username, email, password, age } = req.body;
            let userCreated = await userModel.create({
                username,
                email,
                password: hash,
                age

            })


            res.redirect("/login")
        })
    })
})

Router.get("/logout", (req, res) => {
    res.cookie("token", "");
    res.setInterval(() => {
        res.redirect("/login")
    }, 40000);

});
Router.listen(PORT);