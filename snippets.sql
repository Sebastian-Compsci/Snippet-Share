DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS old_hashes;
DROP TABLE IF EXISTS snippets;
DROP TABLE IF EXISTS likes;
DROP TABLE IF EXISTS following;

CREATE TABLE users (first_name TEXT, last_name TEXT, username TEXT PRIMARY KEY, email_address TEXT, passhash TEXT, salt TEXT);

CREATE TABLE old_hashes (username TEXT, passhash TEXT,
                         FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE);

CREATE TABLE snippets(title TEXT, description TEXT, code TEXT, username TEXT, orderID INTEGER PRIMARY KEY,
                     FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE);

CREATE TABLE likes(username TEXT, snippet_id INTEGER,
                   PRIMARY KEY(username, snippet_id),
                   FOREIGN KEY (snippet_id) REFERENCES snippets(orderID) ON DELETE CASCADE,
                   FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE);

CREATE TABLE following(follower TEXT, following TEXT,
                       PRIMARY KEY(follower, following),
                       FOREIGN KEY(follower) REFERENCES users(username) ON DELETE CASCADE,
                       FOREIGN KEY(following) REFERENCES users(username) ON DELETE CASCADE);
