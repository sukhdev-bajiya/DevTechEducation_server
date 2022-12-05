import mongoose from "mongoose";

const courseSchema = new mongoose.Schema(
  {
    title: {
      type: String,
    },
    description: {
      type: String,
    },
    subDescription: {
      type: String,
    },
    image: {
      type: String,
    },
    fee: {
      type: String,
    },
    subjectItem: {
      type: Number,
    },
    lectureItem: {
      type: Number,
    },
    totalStudent: {
      type: Number,
    },
    subject: [],
  },
  {
    versionKey: false,
    timestamps: true,
  }
);

const devtechCourseModel = mongoose.model(
  "devtechcourse",
  courseSchema,
  "devtechcourses"
);
module.exports[devtechCourseModel];
