import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";



const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

// Middleware setup
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

// Database setup
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/logout", (req, res) => {
    req.logout(function (err) {
      if (err) {
        console.error("Logout error:", err);
        return next(err);
      }
      res.redirect("/");
    });
  });

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT * FROM secrets WHERE user_id = $1", [req.user.id]);
      res.render("secrets.ejs", { secrets: result.rows });
    } catch (err) {
      console.error("Error fetching secrets:", err);
      res.redirect("/");
    }
  } else {
    res.redirect("/login");
  }
});

// Google authentication routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Login and registration routes
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
          res.redirect("/register");
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Error logging in:", err);
              res.redirect("/register");
            } else {
              res.redirect("/secrets");
            }
          });
        }
      });
    }
  } catch (err) {
    console.error("Error during registration:", err);
    res.redirect("/register");
  }
});

// Secret management routes
app.post("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const content = req.body.content;
      await db.query("INSERT INTO secrets (user_id, content) VALUES ($1, $2)", [req.user.id, content]);
      res.redirect("/secrets");
    } catch (err) {
      console.error("Error adding secret:", err);
      res.redirect("/secrets");
    }
  } else {
    res.redirect("/login");
  }
});

// Update Secret Route
app.post("/secrets/:id", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const content = req.body.content;
      const id = req.params.id;
      console.log(`Updating secret with ID ${id} to content: ${content}`); // Debug
      await db.query(
        "UPDATE secrets SET content = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND user_id = $3",
        [content, id, req.user.id]
      );
      res.redirect("/secrets");
    } catch (err) {
      console.error("Error updating secret:", err);
      res.redirect("/secrets");
    }
  } else {
    res.redirect("/login");
  }
});



// Delete Secret Route
app.post("/secrets/:id/delete", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const id = req.params.id;
      await db.query(
        "DELETE FROM secrets WHERE id = $1 AND user_id = $2",
        [id, req.user.id]
      );
      res.redirect("/secrets");
    } catch (err) {
      console.error("Error deleting secret:", err);
      res.redirect("/secrets");
    }
  } else {
    res.redirect("/login");
  }
});

// Passport strategies
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else if (valid) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.error("Error verifying user:", err);
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        console.error("Error with Google authentication:", err);
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

