const express = require("express");
const Jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const bcrypt = require("bcryptjs");
const { devtechUserModel } = require("../model/user.model.js");
const { devtechCourseModel } = require("../model/courses.model.js");
const { devtechLectureModel } = require("../model/lecture.model.js");
const { devtechSubjectModel } = require("../model/subject.model.js");

const UserAuthRouter = express.Router();
const ServerToken = process.env.JwtToken;

UserAuthRouter.get("/getalluserlist", async (req, res) => {
  let token = req.header("Authorization");
  try {
    await Jwt.verify(token, ServerToken, async (error, response) => {
      if (error) {
        // Error part
        let Obj = {
          success: false,
          error: true,
          message: error.message,
        };

        // Send response back
        return res.status(401).send(Obj);
      } else {
        // Success part
        let Obj;

        if (response.role === "admin") {
          // Admin part

          let teacher = await devtechUserModel.find(
            { role: "teacher" },
            {
              password: 0,
              securityAnswer1: 0,
              securityAnswer2: 0,
              lastLogin: 0,
              lastUpdateData: 0,
            }
          );
          let student = await devtechUserModel.find(
            { role: "student" },
            {
              password: 0,
              securityAnswer1: 0,
              securityAnswer2: 0,
              lastLogin: 0,
              lastUpdateData: 0,
            }
          );

          let course = await devtechCourseModel.find();
          let lecture = await devtechLectureModel.find();
          let subject = await devtechSubjectModel.find();

          teacher = CryptoJS.AES.encrypt(
            JSON.stringify(teacher),
            token
          ).toString();
          student = CryptoJS.AES.encrypt(
            JSON.stringify(student),
            token
          ).toString();
          course = CryptoJS.AES.encrypt(
            JSON.stringify(course),
            token
          ).toString();
          lecture = CryptoJS.AES.encrypt(
            JSON.stringify(lecture),
            token
          ).toString();
          subject = CryptoJS.AES.encrypt(
            JSON.stringify(subject),
            token
          ).toString();

          Obj = {
            success: true,
            error: false,
            teacher,
            student,
            course,
            lecture,
            subject,
          };
        } else if (response.role === "teacher") {
          // Teacher part

          let student = await devtechUserModel.find(
            { role: "student" },
            {
              password: 0,
              securityAnswer1: 0,
              securityAnswer2: 0,
              lastLogin: 0,
              lastUpdateData: 0,
            }
          );
          let course = await devtechCourseModel.find();
          let lecture = await devtechLectureModel.find();
          let subject = await devtechSubjectModel.find();

          student = CryptoJS.AES.encrypt(
            JSON.stringify(student),
            token
          ).toString();
          course = CryptoJS.AES.encrypt(
            JSON.stringify(course),
            token
          ).toString();
          lecture = CryptoJS.AES.encrypt(
            JSON.stringify(lecture),
            token
          ).toString();
          subject = CryptoJS.AES.encrypt(
            JSON.stringify(subject),
            token
          ).toString();

          Obj = {
            success: true,
            error: false,
            student,
            course,
            lecture,
            subject,
          };
        } else if (response.role === "student") {
          // User part
          let course = await devtechCourseModel.find();
          let subject = await devtechSubjectModel.find();
          let lecture = await devtechLectureModel.find();

          course = CryptoJS.AES.encrypt(
            JSON.stringify(course),
            token
          ).toString();
          subject = CryptoJS.AES.encrypt(
            JSON.stringify(subject),
            token
          ).toString();
          lecture = CryptoJS.AES.encrypt(
            JSON.stringify(lecture),
            token
          ).toString();

          Obj = {
            success: true,
            error: false,
            course,
            subject,
            lecture,
          };
        } else {
          Obj = {
            success: false,
            error: true,
            message: "Invalid Role",
          };
          return res.status(401).send(Obj);
        }

        return res.status(201).send(Obj);
      }
    });
  } catch (error) {
    // Error part
    let Obj = {
      success: false,
      error: true,
      message: error.message,
    };

    // Send response back
    return res.status(401).send(Obj);
  }
});
UserAuthRouter.post("/add/newuser", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
    await Jwt.verify(token, ServerToken, async (error, response) => {
      if (error) {
        // Error part
        let Obj = {
          status: "error",
        };
        // Send response back
        return res.status(401).send(Obj);
      } else {
        // Success part
        let Obj;
        // Update email, username, flag and password
        data.email = data.email.toLowerCase();
        data.username = Date.now();
        data.password = data.email.split("@")[0];
        data.userDeactive = false;

        const myPassword = data.password;

        // Convert password to secure password
        data.password = await bcrypt.hash(data.password, 10);

        const { number, email } = data;
        const user = await devtechUserModel.findOne({
          $or: [{ number }, { email: { $regex: email, $options: "i" } }],
        });

        if (user || response.role === "student") {
          // Output Obj User already exists
          Obj = {
            status: "false",
          };
        } else {
          // Add new user
          const devtechUser = devtechUserModel(data);
          await devtechUser.save();

          fetch(
            `https://script.google.com/macros/s/AKfycbzXTeE18f404PCyVtuK4Sw5-8dfDTIyFfbDdKEKjRP22KnqdG1DnDX1bWIGwL27HhZcaA/exec?Name=${data.name}&Email=${email}&Number=${number}&Template=<div><p><b> Dear ${data.name} </b>,</p><p>Greetings from <b> <i> Dev Tech Education! </i> </b> </p><p>Hope you are doing well,</p><p>Please find below the important details regarding your education journey</p><p>Important Details:-</p>Course Platform Username : <b> ${data.username} </b><br>Course Platform Password : <b> ${myPassword} </b> <br>Course Platform Link : <a href="https://devtecheducation.netlify.app" target="_blank" >https://devtecheducation.netlify.app</a><br></p><p>You can write to us at <a href="mailto:devtecheducation@gmail.com" target="_blank">devtecheducation@gmail.com</a> for any additional information or queries</p><p>Happy Learning!</p><p>Regards,<br><b><i> Team Dev Tech Education </i></b></p></div>&Subject=Dev Tech Education Online Course Platform Login Credentials`
          );

          // Output Obj User created successfully
          Obj = {
            status: "true",
            error: false,
            message: `User created successfully, Username and password send successfully on ${email}`,
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
    };
    // Send response back
    return res.status(401).send(Obj);
  }
});
UserAuthRouter.post("/deactive", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
    await Jwt.verify(token, ServerToken, async (error, response) => {
      if (error) {
        // Error part
        let Obj = {
          status: "error",
        };
        // Send response back
        return res.status(401).send(Obj);
      } else {
        // Success part
        let Obj;

        if (response.role !== "student") {
          // Add new user
          await devtechUserModel.findByIdAndUpdate(
            { _id: data.user },
            {
              userDeactive: data.ac,
            }
          );

          // Output Obj
          Obj = {
            status: "true",
          };
        } else {
          Obj = {
            status: "false",
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
    };
    // Send response back
    return res.status(401).send(Obj);
  }
});
UserAuthRouter.post("/edit", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
    await Jwt.verify(token, ServerToken, async (error, response) => {
      if (error) {
        // Error part
        let Obj = {
          status: "error",
        };
        // Send response back
        return res.status(401).send(Obj);
      } else {
        // Success part
        let Obj;
        data.email = data.email.toLowerCase();
        const { username, email, number } = req.body;
        const user = await devtechUserModel.find({
          $or: [
            { username },
            { number },
            { email: { $regex: email, $options: "i" } },
          ],
        });

        if (user.length === 1 && response.role !== "student") {
          // update user
          await devtechUserModel.findByIdAndUpdate(
            { _id: data.user },
            {
              name: data.name,
              email: data.email,
              number: data.number,
            }
          );

          // Output Obj
          Obj = {
            status: "true",
          };
        } else {
          // Output Obj
          Obj = {
            status: "false",
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
    };
    // Send response back
    return res.status(401).send(Obj);
  }
});

// export default UserAuthRouter;

module.exports = { UserAuthRouter };
