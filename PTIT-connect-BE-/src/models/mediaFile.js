"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class MediaFile extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      MediaFile.belongsTo(models.Post, { foreignKey: "post_id" });
    }
  }
  MediaFile.init(
    {
      file_id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
      },
      post_id: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
          model: "posts",
          key: "post_id"
        }
      },
      file_content: DataTypes.BLOB("medium"),
    },
    {
      sequelize,
      modelName: "MediaFile",
    }
  );
  return MediaFile;
};
