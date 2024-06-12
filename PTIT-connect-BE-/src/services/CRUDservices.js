import bcrypt from "bcryptjs";
import db from "../models/index";
const salt = bcrypt.genSaltSync(10);

let createUser = async (data) => {
  return new Promise(async (resolve, reject) => {
    try {
      data.password = await hashPassword(data.password);
      console.log(data);
      await db.User.create({
        user_id: data.id,
        name: data.firstName,
        profile_name: data.profileName,
        email: data.email,
        password: data.password,
        gender: data.gender,
        dob: data.dob,
        role: data.role,
      });
      resolve("new user added");
    } catch (error) {
      console.log(error);
      reject(error);
    }
  });
};

let hashPassword = (password) => {
  return new Promise(async (resolve, reject) => {
    try {
      let hashedPassword = await bcrypt.hashSync(password, salt);
      resolve(hashedPassword);
    } catch (error) {
      reject(error);
    }
  });
};

let getUser = (userId) => {
  return new Promise(async (resolve, reject) => {
    if (userId === "ALL") {
      try {
        let users = await db.User.findAll({
          raw: true,
        });
        resolve(users);
      } catch (error) {
        reject(error);
      }
    } else {
      try {
        let user = await db.User.findOne({
          where: {
            id: userId,
          },
        });
        if (user) resolve(user);
        else resolve();
      } catch (error) {
        reject(error);
      }
    }
  });
};

let updateUser = (data, userId) => {
  return new Promise(async (resolve, reject) => {
    try {
      let user = await db.User.findOne({
        where: {
          id: userId,
        },
      });
      if (user) {
        user.name = data.firstName;
        user.lastName = data.lastName;
        user.gender = data.gender;
        user.role = data.role;
        user.dob = data.dob;
        user.save();
        resolve("ok");
      } else {
        resolve("no user found");
      }
    } catch (e) {
      reject(e);
    }
  });
};

let deleteUser = (userId) => {
  return new Promise(async (resolve, reject) => {
    try {
      let user = await db.User.findOne({
        where: {
          id: userId,
        },
      });
      if (user) {
        user.destroy();
        resolve("ok");
      } else {
        resolve("no user found");
      }
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  createUser: createUser,
  getUser: getUser,
  updateUser: updateUser,
  deleteUser: deleteUser,
};
