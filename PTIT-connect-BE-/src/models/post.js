"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
    class Post extends Model {
        /**
         * Helper method for defining associations.
         * This method is not a part of Sequelize lifecycle.
         * The `models/index` file will call this method automatically.
         */
        static associate(models) {
            Post.belongsTo(models.User, { foreignKey: "author", sourceKey: "user_id" });
        }
    }
    Post.init(
        {
            post_id: {
                type: DataTypes.UUID,
                allowNull: false,
                primaryKey: true,
            },
            author: {
                type: DataTypes.STRING,
                allowNull: false,
                references: {
                    model: "users",
                    key: "user_id",
                }
            },
            content: DataTypes.TEXT,
        },
        {
            sequelize,
            modelName: "Post",
        }
    );
    return Post;
};
