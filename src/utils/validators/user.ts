import { Types } from 'mongoose';
import type { IUser } from "../../schemas/user.js";
import { emailValidator } from './user/email.js';
import { rawPasswordValidator } from './user/password.js';
import { usernameValidator } from './user/username.js';

export class UserValidators<R extends readonly string[]> implements UserValidatorObject<R> {
    constructor(
        private _roles: R,
        customValidators: CustomizableUserValidatorObject = {}
        ) {
            if (customValidators.email) {
                this.email = (v: string | undefined) => v ? customValidators.email!(v) : false;
            }
            if (customValidators.username) {
                this.username = customValidators.username;
            }
            if (customValidators.password) {
                this.password = customValidators.password;
            }
        }

    _id = Types.ObjectId.isValid;
    active = (v: boolean) => typeof v === 'boolean';
    createdAt = (v: number) => typeof v === 'number';
    createdBy = (v: Types.ObjectId | string) => Types.ObjectId.isValid(v);
    email: ValidatorFn<string | undefined> = (v: string | undefined) => v ? emailValidator(v) : false; // Added type annotation to allow overriding in constructor
    id = (v: number) => typeof v === 'number';
    password: ValidatorFn<string> = (v: string) => rawPasswordValidator(v); // Added type annotation to allow overriding in constructor
    roles = (v: readonly string[]) => v.every(role => this._roles.includes(role));
    updatedAt = (v: number) => typeof v === 'number';
    updatedBy = (v: Types.ObjectId | string) => Types.ObjectId.isValid(v);
    username: ValidatorFn<string> = (v: string) => usernameValidator(v); // Added type annotation to allow overriding in constructor
}

export type ValidatorFn<T> = (v: T) => boolean | Promise<boolean>;

export type UserValidatorObject<R extends readonly string[]> = {
    [path in keyof Omit<IUser<R>, 'password'>]: ValidatorFn<IUser<R>[path]>;
} & { password: ValidatorFn<string>; };

export type CustomizableUserValidator = 'email' | 'username' | 'password';
export type CustomizableUserValidatorObject = {
    [path in CustomizableUserValidator]?: ValidatorFn<string>;
};
