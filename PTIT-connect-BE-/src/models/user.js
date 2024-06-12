"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      User.hasMany(models.Follow, { foreignKey: 'follower', as: 'followers' });
      User.hasMany(models.Follow, { foreignKey: 'following', as: 'followings' });
      User.hasMany(models.Post, { foreignKey: "author", sourceKey: "user_id" });
    }
  }
  User.init(
    {
      user_id: {
        type: DataTypes.STRING,
        allowNull: false,
        primaryKey: true,
      },
      name: DataTypes.STRING,
      profile_name: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      password: DataTypes.STRING,
      gender: DataTypes.STRING,
      dob: DataTypes.DATE,
      image: DataTypes.BLOB('medium'),
      role: DataTypes.INTEGER,
    },
    {
      sequelize,
      modelName: "User",
    }
  );
  return User;
};
