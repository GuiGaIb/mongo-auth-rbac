import dotenv from "dotenv";
import { fileURLToPath, URL } from "url";
import assert from "assert";
import { Types } from 'mongoose';

import { getUserController, type UserCreateObject } from "../controllers/user.js";
import type { LoggerConfig } from "my-logger";
import type { UserDoc } from "../schemas/user.js";

dotenv.config({ path: fileURLToPath(new URL("../../test.env", import.meta.url)) });

describe('Main test suite', () => {
    const loggerConfig: LoggerConfig = { enable: false, name: 'TEST', useHighIntensityColors: true, useTimestampInPrefix: false };
    const userRoles = ["role1", "role2", "role3"] as const;
    type R = typeof userRoles;
    const Users = getUserController({
        uri: process.env.MONGO_URI || '',
        userRoles,
        usersAuthDbName: process.env.MONGO_AUTH_DB_NAME || '',
        usersCollectionName: 'users',
        usersDbCredentials: {
            username: process.env.MONGO_USERNAME || '',
            password: process.env.MONGO_PASSWORD || ''
        },
        usersDbName: 'users_test',
        loggerConfig,
        schemaOptions: {
            loggerConfig
        }
    });

    async function clearUsersCollection() {
        return Users.User.countDocuments()
            .exec()
            .then(async (count) => {
                if (count !== 0) {
                    await Users.User.deleteMany().exec();
                }
            })
    }
    function closeConnection() {
        return Users.connection.close();
    }

    before('Clear users collection', clearUsersCollection);
    after('Disconnect from database', closeConnection);

    const testUserData: UserCreateObject<R> = {
        createdBy: new Types.ObjectId,
        id: 1,
        password: 'aA1!1234',
        username: 'Test User',
        active: true,
        email: 'test@email.com',
        roles: ['role1']
    };

    function createUser() {
        return Users.createUser(testUserData);
    }

    describe('User statics', () => {
        afterEach('Clear users collection', clearUsersCollection);



        describe('authWithEmail', () => {
            it('should fail if no user with the given email exists', async () => {
                const email = 'test@email.com';
                const password = 'testPassword';

                await assert.rejects(() => {
                    return Users.authWithEmailAndPassword(email, password);
                });
            });

            it('should fail if the given password is incorrect', async () => {
                const user = await createUser();
                const email = user.email as string;
                const password = 'testPassword';

                await assert.rejects(() => {
                    return Users.authWithEmailAndPassword(email, password + '1');
                });
            });

            it('should succeed if the given password is correct', async () => {
                const user = await createUser();
                const email = user.email as string;
                const password = testUserData.password;

                const result = await Users.authWithEmailAndPassword(email, password);
                assert.strictEqual(result.id, user.id);
            });
        });

        describe('authWithUsername', () => {
            it('should fail if no user with the given username exists', async () => {
                const username = 'testUsername';
                const password = 'testPassword';

                await assert.rejects(() => {
                    return Users.authWithUsernameAndPassword(username, password);
                });
            });

            it('should fail if the given password is incorrect', async () => {
                const user = await createUser();
                const username = user.username;
                const password = 'testPassword';

                await assert.rejects(() => {
                    return Users.authWithUsernameAndPassword(username, password + '1');
                });
            });

            it('should succeed if the given password is correct', async () => {
                const user = await createUser();
                const username = user.username;
                const password = testUserData.password;

                const result = await Users.authWithUsernameAndPassword(username, password);
                assert.strictEqual(result.id, user.id);
            });
        });

        describe('getById', () => {
            it('should fail if no user with the given id exists', async () => {
                const id = 1;

                await assert.rejects(() => {
                    return Users.User.getById(id);
                });
            });

            it('should succeed if a user with the given id exists', async () => {
                const user = await createUser();
                const id = user.id;

                const result = await Users.User.getById(id);
                assert.strictEqual(result.id, user.id);
            });
        });

        describe('getByUsername', () => {
            it('should fail if no user with the given username exists', async () => {
                const username = 'testUsername';

                await assert.rejects(() => {
                    return Users.User.getByUsername(username);
                });
            });

            it('should succeed if a user with the given username exists', async () => {
                const user = await createUser();
                const username = user.username;

                const result = await Users.User.getByUsername(username);
                assert.strictEqual(result.id, user.id);
            });
        });

        describe('getByEmail', () => {
            it('should fail if no user with the given email exists', async () => {
                const email = 'testEmail';

                await assert.rejects(() => {
                    return Users.User.getByEmail(email);
                });
            });

            it('should succeed if a user with the given email exists', async () => {
                const user = await createUser();
                const email = user.email as string;

                const result = await Users.User.getByEmail(email);
                assert.strictEqual(result.id, user.id);
            });
        });

    });

    describe('User instance methods', () => {
        afterEach('Clear users collection', clearUsersCollection);

        let user = createUser() as unknown as UserDoc<R>;
        before(async () => {
            user = await (user as unknown as Promise<UserDoc<R>>);
        });

        describe('comparePassword', () => {
            it('returns false if the given password is incorrect', async () => {
                const password = testUserData.password + '1';

                const result = await user.comparePassword(password);
                assert.strictEqual(result, false);
            });

            it('returns true if the given password is correct', async () => {
                const password = testUserData.password;

                const result = await user.comparePassword(password);
                assert.strictEqual(result, true);
            });
        });

        describe('toggleActive', () => {
            it('toggles the active property when called with no argument', () => {
                const active = user.active;
                user.toggleActive();
                assert.strictEqual(user.active, !active);

                user.active = active;
            });

            it('sets the active property to the given argument', () => {
                const active = user.active;

                user.toggleActive(!active);
                assert.strictEqual(user.active, !active);

                user.toggleActive(active);
                assert.strictEqual(user.active, active);
            });
        });

        describe('addRole', () => {
            it('adds the given role to the user', () => {
                const role = userRoles[1];

                user.addRole(role);
                const result = user.hasRole(role);
                user.removeRole(role);

                assert.strictEqual(result, true);
            });
        });

        describe('removeRole', () => {
            it('removes the given role from the user', () => {
                const role = userRoles[1];

                user.addRole(role);
                user.removeRole(role);
                const result = user.hasRole(role);

                assert.strictEqual(result, false);
            });
        });

        describe('hasRole', () => {
            it('returns false if the user does not have the given role', () => {
                const result = user.hasRole('role2');
                assert.strictEqual(result, false);
            });

            it('returns true if the user has the given role', () => {
                const role = 'role1';

                const result = user.hasRole(role);
                assert.strictEqual(result, true);
            });
        });

        describe('hasRoles', () => {
            it('returns false if the user does not have all of the given roles', () => {
                const result = user.hasRoles(['role1', 'role2']);
                assert.strictEqual(result, false);
            });

            it('returns true if the user has all of the given roles', () => {
                user.addRole('role3');

                const result = user.hasRoles(['role1', 'role3']);
                user.removeRole('role3');

                assert.strictEqual(result, true);
            });
        });

        describe('updatePassword', () => {
            it('throws an error if the given password is invalid', async () => {
                const password = 'invalidPassword';

                await assert.rejects(() => {
                    return user.updatePassword(password);
                });
            });

            it('updates the password if the given password is valid', async () => {
                const newPassword = 'aA1!12345';

                await user.updatePassword(newPassword);
                const result = await user.comparePassword(newPassword);
                await user.updatePassword(testUserData.password);

                assert.strictEqual(result, true);
            });
        })
    });
});
