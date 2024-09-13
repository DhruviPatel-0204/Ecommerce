import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";
import Razorpay from 'razorpay';



const app = express();
const port = 3000;
const saltRounds = 10;
env.config();
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY,
});
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/home",(req,res)=>{
  res.render("secrets.ejs")
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get("/auth/google/travel", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Error logging in user:", err);
            }
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/stationery", (req, res) => {
  res.render("stationery.ejs");
});
app.post("/books", (req, res) => {
  res.render("books.ejs");
});
app.post("/buy", (req, res) => {
  const amount = req.body.price * 100;
  req.session.itemAmount = amount; // Store amount in session
  res.render('payment.ejs', { itemAmount: amount, razorpayKey: process.env.RAZORPAY_KEY });
});

app.post("/address", async (req, res) => {
  const address = req.body.address;
  try {
    if (!address) {
      return res.status(400).json({ error: "Address is required" });
    }
    const result = await db.query(
      "UPDATE users SET address = $1 WHERE email = $2 RETURNING *",
      [address, req.user.email] // Use req.user.email
    );
    res.render("payment1.ejs", { itemAmount: req.session.itemAmount,razorpayKey: process.env.RAZORPAY_KEY });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/addtocart", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  const { id, name, price, image } = req.body;
  try {
    await db.query(
      "INSERT INTO cart_items (user_id, product_id, name, price, image) VALUES ($1, $2, $3, $4, $5)",
      [req.user.email, id, name, price, image] // Use req.user.email
    );
    res.redirect("/addtocart");
  } catch (error) {
    console.error("Error adding to cart:", error);
    res.status(500).send("Server error");
  }
});

app.post("/remove", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  const { id } = req.body;
  try {
    // Ensure `req.user.email` is available
    if (!req.user || !req.user.email) {
      throw new Error("User not authenticated or email not found.");
    }

    // Delete the specific item from the cart
    await db.query(
      'DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2',
      [req.user.email, id]
    );

    res.redirect("/addtocart");
  } catch (error) {
    console.error("Error removing item from cart:", error);
    res.status(500).send("Server error");
  }
});

app.get("/addtocart", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  let b = 0; // Declare `b` here
  const cart = [];
  try {
    const result = await db.query(
      "SELECT product_id, name, price, image FROM cart_items WHERE user_id = $1",
      [req.user.email] // Use req.user.email
    );

    result.rows.forEach((row) => {
      cart.push(row);
      let c = parseFloat(row.price) * 100; // Ensure price is a number
      b += c;
    });

    req.session.itemAmount = b; // Store total amount in session
    res.render("addtocart", { cart });
  } catch (error) {
    console.error("Error retrieving cart items:", error);
    res.status(500).send("Server error");
  }
});

app.get("/cart", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  const cart = [];
  try {
    const result = await db.query(
      "SELECT product_id, name, price, image FROM cart_items WHERE user_id = $1",
      [req.user.email] // Use req.user.email
    );

    result.rows.forEach((row) => {
      cart.push(row);
    });

    res.render("addtocart", { cart });
  } catch (error) {
    console.error("Error retrieving cart items:", error);
    res.status(500).send("Server error");
  }
});

app.post("/buyall", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  let b = 0; // Declare `b` here
  const cart = [];

  try {
    const result = await db.query(
      "SELECT product_id, name, price, image FROM cart_items WHERE user_id = $1",
      [req.user.email] // Use req.user.email
    );

    result.rows.forEach((row) => {
      cart.push(row);
      let c = parseFloat(row.price) * 100; // Ensure price is a number
      b += c;
    });

    req.session.itemAmount = b; // Store total amount in session
    res.render('payment.ejs', { itemAmount: b });
  } catch (error) {
    console.error("Error retrieving cart items:", error);
    res.status(500).send("Server error");
  }
});

passport.use("local", new Strategy(async function verify(username, password, cb) {
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, valid) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        }
        if (valid) {
          return cb(null, user);
        }
        return cb(null, false);
      });
    } else {
      return cb("User not found");
    }
  } catch (err) {
    console.log(err);
    return cb(err);
  }
}));

passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/travel",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
},
async (accessToken, refreshToken, profile, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE email=$1", [profile.email]);
    if (result.rows.length === 0) {
      const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
        profile.email, "google"
      ]);
      return cb(null, newUser.rows[0]);
    } else {
      return cb(null, result.rows[0]);
    }
  } catch (err) {
    console.error(err);
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
