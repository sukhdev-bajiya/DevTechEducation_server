const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    number: {
      type: Number,
      required: true,
    },
    username: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    dateofbirth: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      required: true,
    },
    userDeactive: {
      type: Boolean,
    },
    postAddress: {
      address: {
        type: String,
      },
      city: {
        type: String,
      },
      state: {
        type: String,
      },
      country: {
        type: String,
      },
      pincode: {
        type: Number,
      },
    },
    courses: [],
    lastUpdateData: [],
    lastLogin: [],
  },
  {
    versionKey: false,
    timestamps: true,
  }
);

const devtechUserModel = mongoose.model(
  "devtechUser",
  userSchema,
  "devtechUsers"
);
// export default devtechUserModel;

module.exports = { devtechUserModel };
