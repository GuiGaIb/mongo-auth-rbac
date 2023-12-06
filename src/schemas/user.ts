import argon2 from 'argon2';
import { Schema, Types, type HydratedDocument, type Model, type QueryWithHelpers, type SchemaOptions } from 'mongoose';

import { emailValidator } from '../utils/validators/email.js';
import { argon2idHashValidator, rawPasswordValidator } from '../utils/validators/password.js';
import { usernameValidator } from '../utils/validators/username.js';

export const getUserSchema = <R extends readonly string[]>(roles: R, options: UserSchemaOptions = { }) => {
    const schema: UserSchema<R> = new Schema(
        {
            id: {
                type: String,
                required: true,
                unique: true,
                immutable: true
            },
            active: {
                type: Boolean,
                required: true,
                default: true
            },
            email: {
                type: String,
                required: false,
                unique: true,
                sparse: true,
                validate: {
                    validator: options.validators?.email ?? emailValidator
                }
            },
            username: {
                type: String,
                required: true,
                unique: true,
                validate: {
                    validator: options.validators?.username ?? usernameValidator
                }
            },
            // @ts-ignore - TS will raise an error: StringConstructor is not compatible with type readonly string
            roles: {
                type: [String],
                default: [],
                enum: roles
            },
            password: {
                hash: {
                    type: String,
                    required: true,
                    validate: {
                        validator: argon2idHashValidator
                    }
                },
                updatedAt: {
                    type: Number,
                    default: Date.now
                }
            },
            createdAt: {
                type: Number,
                default: Date.now,
                immutable: true
            },
            createdBy: {
                type: Schema.Types.ObjectId,
                ref: 'User',
                required: true,
                immutable: true
            },
            updatedAt: {
                type: Number,
                default: Date.now
            },
            updatedBy: {
                type: Schema.Types.ObjectId,
                ref: 'User',
                required: false
            },
            _id: {
                type: Schema.Types.ObjectId,
                required: true,
                unique: true,
                immutable: true,
                default: () => new Types.ObjectId()
            }
        },
        {
            methods: {
                comparePassword(this: UserDoc<R>, password) {
                    return argon2.verify(this.password.hash, password);
                },
                toggleActive(this: UserDoc<R>, active) {
                    const newActive = active ?? !this.active;
                    this.active = newActive;
                    return this;
                },
                hasRole(this: UserDoc<R>, role) {
                    return this.roles.includes(role);
                },
                hasRoles(this: UserDoc<R>, roles) {
                    return roles.every(role => this.hasRole(role));
                },
                addRole(this: UserDoc<R>, role) {
                    if (this.hasRole(role)) return this;
                    this.roles.push(role);
                    return this;
                },
                removeRole(this: UserDoc<R>, role) {
                    if (!this.hasRole(role)) return this;
                    this.roles = this.roles.filter(r => r !== role);
                    return this;
                },
                async updatePassword(this: UserDoc<R>, password) {
                    if (!(options.validators?.password ?? rawPasswordValidator)(password))
                        throw new Error(`New password validation failed`);
                    const hash = await argon2.hash(password);
                    this.password.hash = hash;
                    this.password.updatedAt = Date.now();
                    return this;
                }
            },
            statics: {
                async authWithEmail(this: UserModel<R> & UserStatics<R>, email, password) {
                    try {
                        const queryResult = await this.find().byEmail(email).active().exec();
                        const user = queryResult[0];
                        if (!user) throw new Error;
                        if (!await user.comparePassword(password)) throw new Error;
                        return user;
                    } catch (error) {
                        throw new Error(`Invalid credentials.`);
                    }
                },
                async getById(this: UserModel<R> & UserStatics<R>, id) {
                    const user = await this.findOne({ id }).exec();
                    if (!user) throw new Error(`User with id ${id} not found.`);
                    return user;
                },
                async getByEmail(this: UserModel<R> & UserStatics<R>, email) {
                    const user = await this.findOne({ email }).exec();
                    if (user) return user;
                    throw new Error(`User with email ${email} not found.`)
                },
                async getByUsername(this: UserModel<R> & UserStatics<R>, username) {
                    const user = await this.findOne({ username }).exec();
                    if (user) return user;
                    throw new Error(`User with username ${username} not found.`)
                }
            },
            query: {
                active(this: UserQWH<R, any>) {
                    return this.where({ active: true })
                },
                inactive(this: UserQWH<R, any>) {
                    return this.where({ active: false })
                },
                byEmail(this: UserQWH<R, any>, email) {
                    return this.where({ email })
                }
            },
            ...options.mongooseSchemaOptions ?? {}
        }
    )
    return schema;
};

export interface IUser<R extends readonly string[]> {
    id          : string;
    active      : boolean;
    email?      : string;
    roles       : UserRoles<R>;
    username    : string;

    _id         : Types.ObjectId;
    password    : UserPassword;

    createdAt   : number;
    createdBy   : Types.ObjectId;
    updatedAt   : number;
    updatedBy   : Types.ObjectId;
}
export type UserRole<R extends readonly string[]> = R[number];
export type UserRoles<R extends readonly string[]> = UserRole<R>[];
export type UserPassword = {
    hash        : string;
    updatedAt   : number;
}

export type UserSchema<R extends readonly string[]> = Schema<
    IUser<R>,
    UserModel<R>,
    UserMethods<R>,
    UserQueryHelpers<R>,
    {},
    UserStatics<R>>;
export type UserModel<R extends readonly string[]> = Model<
    IUser<R>,
    UserQueryHelpers<R>,
    UserMethods<R>,
    {},
    UserDoc<R>>;
export type UserDoc<R extends readonly string[]> = HydratedDocument<IUser<R>, UserMethods<R> & {}, UserQueryHelpers<R>>;

export interface UserMethods<R extends readonly string[]> {
    /**
     * Compare the provided password with the user's password hash.
     * @param password The password to compare.
     */
    comparePassword(password: string): Promise<boolean>;

    /**
     * Toggle the user's active status.
     * @param active The new active status. If not provided, the active status will be toggled.
     */
    toggleActive(active?: boolean): UserDoc<R>;

    /**
     * Check if the user has a specific role.
     */
    hasRole(role: UserRole<R>): boolean;

    /**
     * Check if the user has all of the provided roles.
     * @param roles
     */
    hasRoles(roles: UserRoles<R>): boolean;

    /**
     * Add a role to the user.
     * @param role The role to add.
     */
    addRole(role: UserRole<R>): UserDoc<R>;

    /**
     * Remove a role from the user.
     * @param role The role to remove.
     */
    removeRole(role: UserRole<R>): UserDoc<R>;

    /**
     * Update the user's password.
     * @param password The new password.
     */
    updatePassword(password: string): Promise<UserDoc<R>>;
}
export interface UserStatics<R extends readonly string[]> {
    /**
     * Authenticate a user with an email and password.
     * @param email The user's email.
     * @param password The user's plain text password.
     */
    authWithEmail(email: string, password: string): Promise<UserDoc<R>>;

    /**
     * Get a user by id.
     * @param id The user's id.
     * @throws If the user is not found.
     */
    getById(id: string): Promise<UserDoc<R>>;

    /**
     * Get a user by email.
     * @param email The user's email.
     * @throws If the user is not found.
     */
    getByEmail(email: string): Promise<UserDoc<R>>;

    /**
     * Get a user by username.
     * @param username The user's username.
     * @throws If the user is not found.
     */
    getByUsername(username: string): Promise<UserDoc<R>>;
}
export type UserQWH<R extends readonly string[], RT = any> = QueryWithHelpers<RT, UserDoc<R>, UserQueryHelpers<R>>;
export interface UserQueryHelpers<R extends readonly string[]> {
    byEmail(email: string | RegExp): UserQWH<R, UserDoc<R>[]>;
    active(): UserQWH<R, UserDoc<R>[]>;
    inactive(): UserQWH<R, UserDoc<R>[]>;
}

export interface UserSchemaOptions {
    mongooseSchemaOptions?: Omit<SchemaOptions, 'methods' | 'query' | 'statics' | 'virtuals'>;
    validators?: {
        email?: (v:string) => Promise<boolean> | boolean;
        password?: (v:string) => Promise<boolean> | boolean;
        username?: (v:string) => Promise<boolean> | boolean;
    }
}
