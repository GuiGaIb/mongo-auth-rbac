/**
 * Default email validator function. This function uses a regular expression to validate the email address.
 * The regex checks for the following:
 * * The email address must start with a sequence of characters that does not include special characters.
 * * This sequence of characters can be followed by one or more sequences that start with a dot (.) and are followed by one or more characters that are not special characters.
 * * After this, the @ symbol must appear.
 * * Following the @ symbol, there should be another sequence of characters that does not include special characters. This sequence can be followed by one or more sequences that start with a dot (.) and are followed by two or more alphabetic characters.
 *
 * @param email
 * @returns
 */
export function emailValidator(email: string): boolean {
    return !!email
        .toLowerCase()
        .match(
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        );
};
