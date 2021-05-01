const express = require("express");
const { check, body } = require("express-validator"); //validator has subpackages, check is use for all the validation logic u want to add
// the javascript destructuring is for extract just the checkfuncion due to 'require' will return a javascript object
const authController = require("../controllers/auth");

const User = require("../models/user");

const router = express.Router();

router.get("/login", authController.getLogin);

router.get("/signup", authController.getSignup);

router.post(
  "/login",
  [
    check("email")
      .isEmail()
      .withMessage("Please enter a valir email address.")
      .normalizeEmail()
      .custom(value => {
        return User.findOne({ email: value }).then(user => {
          if (!user) {
            return Promise.reject("Invalid Email or Password.").then(() =>
              res.redirect("/login")
            );
          }
        });
      }),
    body(
      "password",
      "Please enter a password with only numbers and text and at least 5 characters"
    )
      .isAlphanumeric()
      .isLength({ min: 5 })
      .trim()
  ],
  authController.postLogin
);

router.post(
  "/signup",
  [
    check("email")
      .isEmail()
      .withMessage("Please enter a valid email.")
      .normalizeEmail()
      .custom((value, { req }) => {
        // if (value === 'test@test.com') {
        //     throw new Error('This email is invalid mi papa')
        // }
        // return true
        return User.findOne({ email: value }).then((userDoc) => {
          if (userDoc) {
            //this is for async validation
            return Promise.reject(
              "E-Mail exists already, please pick a different one."
            ); //custom takes this reject as an error
          }
        });
      }),
    body(
      "password",
      "Please enter a password with only numbers and text and at least 5 characters."
    ) //default message for all the checking requierments
      .isLength({ min: 5 })
      .trim()
      .isAlphanumeric(),
    body("confirmPassword")
    .trim()
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords have to match!");
      }
      return true;
    }),
  ],
  authController.postSignup
);

router.post("/logout", authController.postLogout);

router.get("/reset", authController.getReset);

router.post("/reset", authController.postReset);

router.get("/reset/:token", authController.getNewPassword);

router.post("/new-password", authController.postNewPassword);

module.exports = router;
