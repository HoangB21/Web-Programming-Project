"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
    class Comment extends Model {
        /**
         * Helper method for defining associations.
         * This method is not a part of Sequelize lifecycle.
         * The `models/index` file will call this method automatically.
         */
        static associate(models) {
            Comment.belongsTo(models.User, { foreignKey: "owner" });
            Comment.belongsTo(models.Post, { foreignKey: "post_id" });
        }
    }
    Comment.init(
        {
            id: {
                type: DataTypes.INTEGER,
                autoIncrement: true,
                primaryKey: true,
            },
            owner: DataTypes.STRING,
            post_id: DataTypes.STRING,
            content: DataTypes.TEXT,
        },
        {
            sequelize,
            modelName: "Comment",
        }
    );
    return Comment;
};
