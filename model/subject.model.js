import mongoose from "mongoose";

const subjectSchema = new mongoose.Schema(
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
    courses: [],
    rating: {
      type: Number,
    },
    lectureItem: {
      type: Number,
    },
    lectures: [],
  },
  {
    versionKey: false,
    timestamps: true,
  }
);

const devtechSubjectModel = mongoose.model(
  "devtechsubject",
  subjectSchema,
  "devtechsubjects"
);
module.exports[devtechSubjectModel];
