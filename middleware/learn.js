const express = require("express");
const Jwt = require("jsonwebtoken");
const { devtechUserModel } = require("../model/user.model.js");
const { devtechCourseModel } = require("../model/courses.model.js");
const { devtechLectureModel } = require("../model/lecture.model.js");
const { devtechSubjectModel } = require("../model/subject.model.js");
const CryptoJS = require("crypto-js");

const LearnRouter = express.Router();
const ServerToken = process.env.JwtToken;

LearnRouter.post("/add/course", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const { title } = req.body;
        const course = await devtechCourseModel.findOne({ title });

        if (!course && response.role === "admin") {
          // update user
          let devtechCourse = devtechCourseModel(data);
          await devtechCourse.save();
          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});
LearnRouter.post("/edit/course", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const { title } = req.body;
        const id = data.id;
        const course = await devtechCourseModel.find({
          $or: [{ title }, { _id: id }],
        });

        if (course.length === 1 && response.role === "admin") {
          // update user
          delete data.id;
          await devtechCourseModel.findByIdAndUpdate(id, { ...data });

          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});
LearnRouter.post("/delete/course", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const id = data.id;
        if (response.role === "admin") {
          // update user
          await devtechCourseModel.findByIdAndDelete(id);

          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});

LearnRouter.post("/add/subject", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const { title, courses } = req.body;
        const subjectIs = await devtechSubjectModel.findOne({ title });

        if (!subjectIs && response.role === "admin") {
          // update user
          let devtechSubject = devtechSubjectModel(data);
          await devtechSubject.save();

          await devtechCourseModel.update(
            {
              title: { $in: courses },
            },
            { $push: { subject: data.title } }
          );

          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});
LearnRouter.post("/edit/subject", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const { title, courses } = req.body;
        const id = data.id;
        const course = await devtechSubjectModel.find({
          $or: [{ title }, { _id: id }],
        });

        if (course.length === 1 && response.role === "admin") {
          // update user
          delete data.id;
          await devtechSubjectModel.findByIdAndUpdate(id, { ...data });

          await devtechCourseModel.update(
            {
              subject: { $in: data.title },
            },
            { $pull: { subject: data.title } }
          );

          await devtechCourseModel.update(
            {
              title: { $in: courses },
            },
            { $push: { subject: data.title } }
          );
          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});
LearnRouter.post("/delete/subject", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const id = data.id;
        if (response.role === "admin") {
          // update user
          await devtechSubjectModel.findByIdAndDelete(id);

          await devtechCourseModel.update(
            {
              subject: { $in: data.title },
            },
            { $pull: { subject: data.title } }
          );
          await devtechLectureModel.update(
            {
              subject: { $in: data.title },
            },
            { $pull: { subject: data.title } }
          );

          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});

LearnRouter.post("/add/lectures", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const { title, subject } = req.body;
        const lectureIs = await devtechLectureModel.findOne({ title });

        if (!lectureIs && response.role !== "student") {
          // update user
          let devtechLecture = devtechLectureModel(data);
          await devtechLecture.save();

          await devtechSubjectModel.update(
            {
              title: { $in: subject },
            },
            { $push: { lectures: data.title } }
          );
          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});
LearnRouter.post("/edit/lectures", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const { title, subject } = req.body;
        const id = data.id;
        const course = await devtechLectureModel.find({
          $or: [{ title }, { _id: id }],
        });

        if (course.length === 1 && response.role !== "student") {
          // update user
          delete data.id;
          await devtechLectureModel.findByIdAndUpdate(id, { ...data });

          await devtechSubjectModel.update(
            {
              lectures: { $in: data.title },
            },
            { $pull: { lectures: data.title } }
          );

          await devtechSubjectModel.update(
            {
              title: { $in: subject },
            },
            { $push: { lectures: data.title } }
          );
          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});
LearnRouter.post("/delete/lectures", async (req, res) => {
  let token = req.header("Authorization");
  let data = req.body;
  try {
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
        // Success part
        let Obj;
        const id = data.id;
        if (response.role !== "student") {
          // update user
          await devtechLectureModel.findByIdAndDelete(id);

          await devtechSubjectModel.update(
            {
              lectures: { $in: data.title },
            },
            { $pull: { lectures: data.title } }
          );

          // Output Obj
          Obj = {
            status: "success",
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});

LearnRouter.post("/buy/course", async (req, res) => {
  let token = req.header("Authorization");
  let inputData = req.body;
  try {
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
        // Success part
        let Obj;
        if (response.role === "student") {
          // update user

          let allr = await devtechUserModel.find({
            _id: response.id,
            courses: { $in: inputData.title },
          });

          if (allr.length === 0) {
            await devtechUserModel.update(
              {
                _id: response.id,
              },
              { $push: { courses: inputData.title } }
            );
          }

          const devtechUser = await devtechUserModel.findById(
            { _id: response.id },
            {
              securityAnswer1: 0,
              securityAnswer2: 0,
              lastLogin: 0,
              lastUpdateData: 0,
              password: 0,
            }
          );

          const data = CryptoJS.AES.encrypt(
            JSON.stringify(devtechUser),
            token
          ).toString();

          // Output Obj
          Obj = {
            status: "success",
            data,
          };
        } else {
          // Output Obj
          Obj = {
            status: "fail",
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
    return res.status(401).send(Obj);
  }
});

// export default LearnRouter;

module.exports = { LearnRouter };
