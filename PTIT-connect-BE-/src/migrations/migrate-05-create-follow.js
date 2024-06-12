'use strict';
module.exports = {
    up: async (queryInterface, Sequelize) => {
        await queryInterface.createTable('follows', {
            follower: {
                type: Sequelize.STRING,
                primaryKey: true,
                allowNull: false,
                references: {
                    model: 'users',
                    key: 'user_id'
                },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE'
            },
            following: {
                type: Sequelize.STRING,
                primaryKey: true,
                allowNull: false,
                references: {
                    model: 'users',
                    key: 'user_id'
                },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE'
            },
            createdAt: {
                allowNull: false,
                type: Sequelize.DATE
            },
            updatedAt: {
                allowNull: false,
                type: Sequelize.DATE
            }
        });
    },
    down: async (queryInterface, Sequelize) => {
        await queryInterface.dropTable('follows');
    }
};
