import { createConnection, Types, type Connection, type ConnectOptions } from 'mongoose';
import argon2 from 'argon2';
import MyLogger, { type LoggerConfig } from 'my-logger';

import { getUserSchema, type IUser, type UserDoc, type UserModel, type UserRoles, type UserSchemaOptions, type UserStatics } from '../schemas/user.js';
import type { UserValidators, ValidatorFn } from '../utils/validators/user.js';

class UserController<R extends readonly string[]> {
    public usersDbName: string;
    public connection: Connection;
    public User: UserModel<R> & UserStatics<R>;

    private validators: UserValidators<R>;
    public logger: MyLogger;

    constructor(options: UserControllerOptions<R>) {
        this.usersDbName = options.usersDbName;
        this.connection = createConnection(options.uri, {
            auth: {
                username: options.usersDbCredentials.username,
                password: options.usersDbCredentials.password
            },
            authSource: options.usersAuthDbName,
            dbName: options.usersDbName,
            ...options.connectionOptions ?? {}
        });
        const { schema, validators } = getUserSchema(options.userRoles, options.schemaOptions);
        this.User = this.connection.model('User', schema, options.usersCollectionName);
        this.validators = validators;
        this.logger = new MyLogger(options.loggerConfig ?? { enable: false });
    }

    private async validateUserObject(obj: { [path in keyof IUser<R>]?: any }): Promise<boolean> {
        const prefix = ["UserController", "validateUserObject"];
        this.logger.info('Validating user object...', ...prefix);
        this.logger.debug(JSON.stringify(obj), ...prefix);
        let result: boolean = true;
        const paths = Object.keys(obj) as (keyof IUser<R>)[];
        for (const path of paths) {
            if (path === 'roles' && !!obj.roles) {
                if (Array.isArray(obj.roles)) {
                    result = result && this.validators.roles(obj.roles);
                } else if (obj.roles.add || obj.roles.remove || obj.roles.set) {
                    if (obj.roles.add) {
                        if (!Array.isArray(obj.roles.add)) throw new Error(`Invalid type for roles.add (${typeof obj.roles.add})`);
                        result = result && this.validators.roles(obj.roles.add);
                    }
                    if (obj.roles.remove) {
                        if (!Array.isArray(obj.roles.remove)) throw new Error(`Invalid type for roles.remove (${typeof obj.roles.remove})`);
                        result = result && this.validators.roles(obj.roles.remove);
                    }
                    if (obj.roles.set) {
                        if (!Array.isArray(obj.roles.set)) throw new Error(`Invalid type for roles.set (${typeof obj.roles.set})`);
                        result = result && this.validators.roles(obj.roles.set);
                    }
                }
            } else {
                const validator: ValidatorFn<any> = this.validators[path];
                result = result && await validator(obj[path]);
            }
        }
        return result;
    }

    /**
     * Authenticates a user with email and password.
     *
     * @param email - The user's email.
     * @param password - The user's password.
     * @returns A promise that resolves to the authenticated user document.
     * @throws if the user is not found or the password is incorrect.
     */
    public authWithEmailAndPassword(email: string, password: string): Promise<UserDoc<R>> {
        this.logger.info(`Authenticating user with email and password...`, "UserController", "authWithEmailAndPassword");
        return this.User.authWithEmail(email, password);
    }

    /**
     * Authenticates a user with a username and password.
     *
     * @param username - The username of the user.
     * @param password - The password of the user.
     * @returns A Promise that resolves to the authenticated user document.
     * @throws if the user is not found or the password is incorrect.
     */
    public authWithUsernameAndPassword(username: string, password: string): Promise<UserDoc<R>> {
        this.logger.info(`Authenticating user with username and password...`, "UserController", "authWithUsernameAndPassword");
        return this.User.authWithUsername(username, password);
    }

    /**
     * Creates a new user and saves it to the database.
     *
     * @param obj - The user object containing the user details.
     * @returns A promise that resolves to the created user document.
     * @throws An error if the user data validation fails or if there is an error creating the user.
     */
    public async createUser(obj: UserCreateObject<R>): Promise<UserDoc<R>> {
        const prefix = ["UserController", "createUser"];
        this.logger.info(`Creating user...`, ...prefix);
        this.logger.debug(JSON.stringify(obj), ...prefix)
        if (!await this.validateUserObject(obj)) {
            this.logger.error('New user data validation failed.', ...prefix);
            throw new Error('New user data validation failed.');
        }
        const hash = await argon2.hash(obj.password);
        const user: UserDoc<R> = new this.User({...obj, password: { hash }});
        try {
            await user.save();
        } catch (error) {
            const err = error instanceof Error ? error : new Error(String(error));
            this.logger.error('Error creating user: ' + err.message, ...prefix);
            throw error;
        }
        return user;
    }

    /**
     * Finds a user by id or _id, updates it and saves it to the database.
     *
     * @param id - The id or _id of the user.
     * @returns A promise that resolves to the updated user document.
     * @throws if the user is not found or the update data is invalid.
     */
    public async updateUser(id: number | Types.ObjectId, data: UserUpdateObject<R>): Promise<UserDoc<R>> {
        const prefix = ["UserController", "updateUser"];
        this.logger.info(`Updating user...`, ...prefix);
        if (!await this.validateUserObject(data)) {
            const msg = 'User data validation failed.';
            this.logger.error(msg, ...prefix);
            throw new Error(msg);
        }
        let user: UserDoc<R>;
        if (typeof id === 'number') {
            user = await this.User.getById(id);
        } else if (id instanceof Types.ObjectId) {
            const queryResult = await this.User.findOne({ _id: id });
            if (queryResult) {
                user = queryResult;
            } else {
                const msg = `User with id ${id} not found.`;
                this.logger.error(msg, ...prefix);
                throw new Error(msg);
            }
        } else {
            const msg = `Invalid id type: ${typeof id}.`;
            this.logger.error(msg, ...prefix);
            throw new Error(msg);
        }

        user.updatedBy = new Types.ObjectId(data.updatedBy);

        if (data.active !== undefined) {
            user = user.toggleActive(data.active);
        }
        if (data.email !== undefined) {
            user.email = data.email;
        }
        if (data.password) {
            user = await user.updatePassword(data.password);
        }
        if (data.roles) {
            if (data.roles.add && data.roles.add.length) {
                for (const role of data.roles.add) {
                    user = user.addRole(role);
                }
            }
            if (data.roles.remove && data.roles.remove.length) {
                for (const role of data.roles.remove) {
                    user = user.removeRole(role);
                }
            }
            if (data.roles.set && data.roles.set.length) {
                user.roles = data.roles.set;
            }
        }
        if (data.username) {
            user.username = data.username;
        }

        return await user.save();
    }

    /**
     * Deletes a user by their id or _id.
     * @param id - The id of the user to delete. Can be either a number or an ObjectId.
     * @returns A promise that resolves to a boolean indicating whether the deletion was successful.
     * @throws An error if the user with the specified id is not found or if the id is of an invalid type.
     */
    public async deleteUser(id: number | Types.ObjectId): Promise<boolean> {
        const prefix = ["UserController", "deleteUser"];
        this.logger.info(`Deleting user...`, ...prefix);
        let user: UserDoc<R>;
        if (typeof id === 'number') {
            user = await this.User.getById(id);
        } else if (id instanceof Types.ObjectId) {
            const queryResult = await this.User.findOne({ _id: id });
            if (queryResult) {
                user = queryResult;
            } else {
                const msg = `User with id ${id} not found.`;
                this.logger.error(msg, ...prefix);
                throw new Error(msg);
            }
        } else {
            const msg = `Invalid id type: ${typeof id}.`;
            this.logger.error(msg, ...prefix);
            throw new Error(msg);
        }

        const result = await user.deleteOne();
        return result.acknowledged;
    }
}

export function getUserController<R extends readonly string[]>(options: UserControllerOptions<R>): UserController<R> {
    return new UserController(options);
}

export interface UserControllerOptions<R extends readonly string[]> {
    userRoles           : R;
    uri                 : string;
    usersAuthDbName     : string;
    usersDbName         : string;
    usersCollectionName : string;
    usersDbCredentials  : {
                            username: string;
                            password: string;
                          };
    connectionOptions?  : Omit<ConnectOptions, 'auth' | 'user' | 'pass' | 'authSource' | 'dbName'>;
    schemaOptions?      : UserSchemaOptions;
    loggerConfig?       : LoggerConfig;
}

export interface UserCreateObject<R extends readonly string[]> {
    id          : number;
    username    : string;
    password    : string;
    createdBy   : Types.ObjectId | string;

    email?      : string;
    active?     : boolean;
    roles?      : UserRoles<R>;
}

export interface UserUpdateObject<R extends readonly string[]> {
    active?     : boolean;
    roles?      : {
                    add?: UserRoles<R>;
                    remove?: UserRoles<R>;
                    set?: UserRoles<R>;
                  };
    email?      : string;
    username?   : string;
    password?   : string;
    updatedBy   : Types.ObjectId | string;
}
