// models/react.js
'use strict';
const { Model } = require('sequelize');
module.exports = (sequelize, DataTypes) => {
    class React extends Model {
        static associate(models) {
            React.belongsTo(models.User, { foreignKey: 'user_id', as: 'user' });
            React.belongsTo(models.Post, { foreignKey: 'post_id', as: 'post' });
        }
    }
    React.init(
        {
            user_id: {
                type: DataTypes.STRING,
                primaryKey: true,
                allowNull: false,
                references: {
                    model: 'users',
                    key: 'user_id'
                },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE'
            },
            post_id: {
                type: DataTypes.UUID,
                primaryKey: true,
                allowNull: false,
                references: {
                    model: 'posts',
                    key: 'post_id'
                },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE'
            },
        },
        {
            sequelize,
            modelName: 'React',
        }
    );
    return React;
};
