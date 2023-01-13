const express = require("express");
const bcrypt = require("bcryptjs");
const Jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const axios = require("axios");
const { devtechUserModel } = require("../model/user.model.js");

const AuthRouter = express.Router();

const ServerToken = process.env.JwtToken;

// User Signup routes
AuthRouter.post("/signup", async (req, res) => {
  // Get signup information
  const data = req.body;

  // Update email, username, flag and password
  data.email = data.email.toLowerCase();
  data.username = Date.now();
  data.password = data.email.split("@")[0];
  data.userDeactive = false;

  const myPassword = data.password;

  // Convert password to secure password
  data.password = await bcrypt.hash(data.password, 10);

  try {
    // Find user already registered or not
    const { number, email } = data;
    const user = await devtechUserModel.findOne({
      $or: [{ number }, { email: { $regex: email, $options: "i" } }],
    });

    // Output Obj
    let obj;

    if (user) {
      // Output Obj User already exists
      obj = {
        status: "fail",
        message: "User already exists with same number and email",
      };
    } else {
      // Add new user
      const devtechUser = devtechUserModel(data);
      await devtechUser.save();

      // Send mail to user
      await axios.get(
        `https://script.google.com/macros/s/AKfycbzXTeE18f404PCyVtuK4Sw5-8dfDTIyFfbDdKEKjRP22KnqdG1DnDX1bWIGwL27HhZcaA/exec?Name=${data.name}&Email=${email}&Number=${number}&Template=<div><p><b> Dear ${data.name} </b>,</p><p>Greetings from <b> <i> Dev Tech Education! </i> </b> </p><p>Hope you are doing well,</p><p>Please find below the important details regarding your education journey</p><p>Important Details:-</p>Course Platform Username : <b> ${data.username} </b><br>Course Platform Password : <b> ${myPassword} </b> <br>Course Platform Link : <a href="https://devtecheducation.netlify.app" target="_blank" >https://devtecheducation.netlify.app</a><br></p><p>You can write to us at <a href="mailto:devtecheducation@gmail.com" target="_blank">devtecheducation@gmail.com</a> for any additional information or queries</p><p>Happy Learning!</p><p>Regards,<br><b><i> Team Dev Tech Education </i></b></p></div>&Subject=Dev Tech Education Online Course Platform Login Credentials`
      );

      // Output Obj User created successfully
      obj = {
        status: "success",
        message: `User created successfully, Username and password send successfully on ${email}`,
      };
    }
    // Send response back
    return res.status(201).send(obj);
  } catch (error) {
    // Error part
    let obj = {
      status: "error",
      message: error.message,
    };

    // Send response back
    return res.status(500).send(obj);
  }
});

// User Signin routes
AuthRouter.post("/signin", async (req, res) => {
  try {
    // Get signin information
    const { username, password } = req.body;

    // Find user
    const devtechUser = await devtechUserModel.findOne(
      { username },
      {
        lastLogin: 0,
        lastUpdateData: 0,
      }
    );

    // Output Obj
    let Obj;

    // Check user already registered or password same
    if (devtechUser && (await bcrypt.compare(password, devtechUser.password))) {
      // Change password
      devtechUser.password = "Welcome to Dev Tech Education";

      // Create JWT token for user with expire time
      const token = await Jwt.sign(
        {
          id: devtechUser._id.toString(),
          role: devtechUser.role,
        },
        ServerToken,
        { expiresIn: "6h" }
      );

      // Change user data format json to string
      const data = CryptoJS.AES.encrypt(
        JSON.stringify(devtechUser),
        token
      ).toString();

      // Login Successful
      Obj = {
        userDeactive: devtechUser.userDeactive || false,
        status: "success",
        message: "Login Successful",
        user: {
          role: devtechUser.role,
          username: devtechUser.username,
          name: devtechUser.name,
          email: devtechUser.email,
          number: devtechUser.number,
        },
        data,
        token,
      };
    } else {
      // Wrong Credentials
      Obj = {
        status: "fail",
        message: "Wrong Credentials",
        user: {},
      };
    }

    // Send response back
    return res.status(201).send(Obj);
  } catch (error) {
    // Error part
    let Obj = {
      status: "error",
      message: error.message,
    };

    // Send response back
    return res.status(500).send(Obj);
  }
});

// Goto Dashboard routes (user already logged in)
AuthRouter.get("/goto/dashboard", async (req, res) => {
  try {
    let token = req.header("Authorization");
    await Jwt.verify(token, ServerToken, async (error, response) => {
      if (error) {
        // Error part
        let Obj = {
          status: "error",
          message: error.message,
        };

        // Send response back
        return res.status(401).send(Obj);
      } else {
        const devtechUser = await devtechUserModel.findById(
          { _id: response.id },
          {
            lastLogin: 0,
            lastUpdateData: 0,
          }
        );

        // Change password
        devtechUser.password = "Welcome to Dev Tech Education";

        const data = CryptoJS.AES.encrypt(
          JSON.stringify(devtechUser),
          token
        ).toString();

        return res.status(201).send({
          status: "success",
          message: "Login Successful",
          user: {
            role: devtechUser.role,
            username: devtechUser.username,
            name: devtechUser.name,
            email: devtechUser.email,
            number: devtechUser.number,
          },
          data,
        });
      }
    });
  } catch (error) {
    // Error part
    let Obj = {
      status: "error",
      message: error.message,
    };

    // Send response back
    return res.status(500).send(Obj);
  }
});

// Update User Profile routes
AuthRouter.post("/update/profile", async (req, res) => {
  try {
    // Get user information
    let user = req.body;
    let token = req.header("token");

    // Verify token and update data
    await Jwt.verify(token, ServerToken, async (error, response) => {
      if (error) {
        // Error part
        let Obj = {
          status: "error",
          message: error.message,
        };

        // Send response back
        return res.status(500).send(Obj);
      } else {
        // Find user
        const devtechUser = await devtechUserModel.findById({
          _id: response.id,
        });

        // Output Obj
        let Obj;

        // Check password valid or not
        if (await bcrypt.compare(user.oldpassword, devtechUser.password)) {
          // new user data
          let user_date = {
            name: user.name,
            dateofbirth: user.dateofbirth,
            postAddress: user.postAddress,
          };

          user_date.lastUpdateData = [
            ...devtechUser.lastUpdateData,
            devtechUser,
          ];

          // Update Value
          if (user.password !== "") {
            user_date.password = await bcrypt.hash(user.password, 10);
          }

          // Update user
          await devtechUserModel.findByIdAndUpdate(
            { _id: response.id },
            {
              ...user_date,
            }
          );

          // Find user
          const devtechUpdateUser = await devtechUserModel.findById(
            { _id: response.id },
            {
              lastLogin: 0,
              lastUpdateData: 0,
            }
          );

          // Change user data format json to string
          const data = CryptoJS.AES.encrypt(
            JSON.stringify(devtechUpdateUser),
            token
          ).toString();

          // User profile updated successfully
          Obj = {
            status: "success",
            data: {
              status: "success",
              message: "User profile updated successfully",
              user: {
                role: devtechUpdateUser.role,
                username: devtechUpdateUser.username,
                name: devtechUpdateUser.name,
                email: devtechUpdateUser.email,
                number: devtechUpdateUser.number,
              },
              data,
            },
          };
        } else {
          // Wrong Credentials
          Obj = {
            status: "error",
            message: "Wrong Credentials",
          };
        }

        // Send response back
        return res.status(201).send(Obj);
      }
    });
  } catch (error) {
    // Error part
    let Obj = {
      status: "error",
      message: error.message,
    };

    // Send response back
    return res.status(500).send(Obj);
  }
});

// User Get Username routes
AuthRouter.post("/get/username", async (req, res) => {
  try {
    // Get user information
    const { email, number } = req.body;

    // Find user
    const devtechUser = await devtechUserModel.findOne({ email, number });

    // Output Obj
    let Obj;

    if (devtechUser) {
      await axios.get(
        `https://script.google.com/macros/s/AKfycbzXTeE18f404PCyVtuK4Sw5-8dfDTIyFfbDdKEKjRP22KnqdG1DnDX1bWIGwL27HhZcaA/exec?Name=${devtechUser.name}&Email=${devtechUser.email}&Number=${devtechUser.number}&Template=<div><p><b> Dear ${devtechUser.name} </b>,</p><p>Greetings from <b> <i> Dev Tech Education! </i> </b> </p><p>Hope you are doing well,</p>Your Username : <b> ${devtechUser.username} </b><br>Course Platform Link : <a href="https://devtecheducation.netlify.app" target="_blank">https://devtecheducation.netlify.app</a><br><p>You can write to us at <a href="mailto:devtecheducation@gmail.com" target="_blank">devtecheducation@gmail.com</a> for any additional information or queries</p><p>Happy Learning!</p><p>Regards,<br><b><i> Team Dev Tech Education </i></b></p></div>&Subject=Dev Tech Education Genrate Username`
      );
      // Genrate Username
      Obj = {
        status: "success",
        message: "Genrate Username",
      };
    } else {
      // Wrong Credentials
      Obj = {
        status: "fail",
        message: "Wrong Credentials",
      };
    }

    // Send response back
    return res.status(201).send(Obj);
  } catch (error) {
    // Error part

    let Obj = {
      status: "error",
      message: error.message,
    };
    // Send response back
    return res.status(500).send(Obj);
  }
});

// User Reset Password routes
AuthRouter.post("/reset/password", async (req, res) => {
  try {
    // Get user information
    const { username, email, number } = req.body;

    // Find user
    const devtechUser = await devtechUserModel.findOne({
      username,
      email,
      number,
    });

    // Output Obj
    let Obj;

    if (devtechUser) {
      let password = devtechUser.email.split("@")[0];
      password = await bcrypt.hash(password, 10);
      // Update user
      await devtechUserModel.findByIdAndUpdate(
        { _id: devtechUser.id },
        { password: password }
      );

      await axios.get(
        `https://script.google.com/macros/s/AKfycbzXTeE18f404PCyVtuK4Sw5-8dfDTIyFfbDdKEKjRP22KnqdG1DnDX1bWIGwL27HhZcaA/exec?Name=${
          devtechUser.name
        }&Email=${devtechUser.email}&Number=${
          devtechUser.number
        }&Template=<div><p><b> Dear ${
          devtechUser.name
        } </b>,</p><p>Greetings from <b> <i> Dev Tech Education! </i> </b> </p><p>Hope you are doing well,</p>Your New Password : <b> ${
          devtechUser.email.split("@")[0]
        }</b><br>Your Username : <b> ${
          devtechUser.username
        } </b><br>Course Platform Link : <a href="https://devtecheducation.netlify.app" target="_blank">https://devtecheducation.netlify.app</a><br><p>You can write to us at <a href="mailto:devtecheducation@gmail.com" target="_blank">devtecheducation@gmail.com</a> for any additional information or queries</p><p>Happy Learning!</p><p>Regards,<br><b><i> Team Dev Tech Education </i></b></p></div>&Subject=Dev Tech Education Genrate New Password`
      );

      // Go to
      Obj = {
        status: "success",
        message: "Genrate New Password",
      };
    } else {
      // Wrong Credentials
      Obj = {
        status: "fail",
        message: "Wrong Credentials",
      };
    }

    // Send response back
    return res.status(201).send(Obj);
  } catch (error) {
    // Error part
    let Obj = {
      status: "error",
      message: error.message,
    };
    // Send response back
    return res.status(500).send(Obj);
  }
});

module.exports = { AuthRouter };
