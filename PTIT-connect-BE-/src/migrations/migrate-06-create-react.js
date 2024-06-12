// migrations/create-react.js
'use strict';
module.exports = {
    up: async (queryInterface, Sequelize) => {
        await queryInterface.createTable('reacts', {
            user_id: {
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
            post_id: {
                type: Sequelize.UUID,
                primaryKey: true,
                allowNull: false,
                references: {
                    model: 'posts',
                    key: 'post_id'
                },
                // onUpdate: 'CASCADE',
                // onDelete: 'CASCADE'
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
        await queryInterface.dropTable('reacts');
    }
};
