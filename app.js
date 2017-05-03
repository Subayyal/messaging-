var app = require('express')();
var guid = require('guid');
var url = require('url');
var server = require('http').Server(app);
var io = require('socket.io')(server);
var mysql = require('mysql');
var bodyParser = require('body-parser');
var cors = require('cors');
var connection = require('express-myconnection');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passportSocketIo = require("passport.socketio");
var MySqlStore = require('express-mysql-session')(session);
var passport = require('passport');
var flash = require('connect-flash');
var circularJSON = require('circular-json');

require('./config/passport')(passport);

var i = 1;

app.use(function(req, res, next) {
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept');
    if ('OPTIONS' == req.method) {
        res.sendStatus(200);
    } else {
        next();
    }
});
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

var options = {
    host: 'localhost',
    port: 3306,
    user: 'keshri',
    password: 'keshri',
    database: 'session'
};

var sessionConnection = mysql.createConnection(options);

// required for passport
var sessionStore = new MySqlStore({}, sessionConnection);

app.use(cookieParser('mysecret'));
app.use(session({
    key: 'aprimacookie',
    secret: 'mysecret',
    store: sessionStore, //tell express to store session info in the Mysql store
    cookie: { httpOnly: true, maxAge: 2419200000 },
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

io.use(passportSocketIo.authorize({ //configure socket.io
    key: 'aprimacookie',
    secret: 'mysecret', // make sure it's the same than the one you gave to express
    store: sessionStore,
    success: onAuthorizeSuccess, // *optional* callback on success
    fail: onAuthorizeFail // *optional* callback on fail/error
}));

app.use(connection(mysql, {
    host: "localhost",
    user: "keshri",
    password: "keshri",
    database: "messaging"
}, 'request'));

server.listen(4041, function() {
    console.log('server up and running at 4041 port');
});

function onAuthorizeSuccess(data, accept) {
    console.log('successful connection to socket.io');
    // If you use socket.io@1.X the callback looks different
    accept();
}

function onAuthorizeFail(data, message, error, accept) {
    if (error) accept(new Error(message));
    console.log('failed connection to socket.io:', message);
    accept(null, false);

}
var socketList = new Array();
io.on('connection', function(socket) {
    if (socket.request.user.logged_in == false) {
        socket.disconnect();
    }

    socket.on('join-conversation', function(data) {
        console.log('join called');

        passportSocketIo.filterSocketsByUser(io, function(user) {
            return user.logged_in == true;
        }).forEach(function(socket) {
            if (socket.request.user.user_id == data.userId) {
                socket.join(data.group);
                console.log('user ' + data.userId + ' has joined group ' + data.group);
                console.log(io.nsps['/'].adapter.rooms[data.group].length);
            }
        });
    });

    socket.on('new-conversation', function(data) {
        console.log('new-conversation called ');
        passportSocketIo.filterSocketsByUser(io, function(user) {
            return user.logged_in == true;
        }).forEach(function(socket) {
            if (socket.request.user.user_id == data.userId || socket.request.user.user_id == data.hostId) {
                socket.join(data.threadId);
                console.log('user ' + data.userId + ' has joined group ' + data.threadId);
            }
        });
        socket.to(data.threadId).emit('new-conversation-created', { threadId: data.threadId, from: data.hostId });
    });

    socket.on('new-message', function(data) {
        console.log('new-message called');
        socket.to(data.threadId).emit('new-message-receive', { threadId: data.threadId, hostId: data.hostId });
    });

    socket.on('disconnect', function() {
        console.log(socket.request.user.user_id + ' disconnected');
    });
});

app.post('/login', function(req, res, next) {
    console.log('/login called' + req.session.id);
    passport.authenticate('local-login', function(err, user, info) {
        if (err) { return next(err); }
        // Redirect if it fails
        if (!user) { return res.json(user); }
        req.logIn(user, function(err) {
            if (err) { return next(err); }
            // Redirect if it succeeds
            return res.json(user.user_id);

        });
    })(req, res, next);
});

app.get('/logout', function(req, res) {
    console.log('/logout ' + req.session.id);
    req.logout();
    req.session.destroy();
    res.clearCookie('aprimacookie', { path: '/' });
    res.clearCookie('io');
    res.json({ 'success': 'success' });
});

app.get('/checkAuthentication', function(req, res) {
    console.log('/checkAuthentication ' + req.session.id);
    var status = req.isAuthenticated();
    console.log(status);
    res.json({ 'loggedIn': status });
});

//======================================================================================//
//======================================================================================//

app.get('/user/getUserGuid', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        console.log(query);
        var receivedId = query.received_id;
        console.log(receivedId);
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('CALL get_user_id(?,@userId,@status)', [receivedId],
                    function(err, rows, fields) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        var resUser = rows[0];
                        console.log("Result: " + JSON.stringify(resUser));
                        res.json(resUser);
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/getContacts', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var conversation_id = query.conversationId;
        var requestKey = query.requestKey;
        var insertSql;
        var val;
        console.log(JSON.stringify(query));
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (requestKey == 'addList') {
                    console.log('In addlist');
                    insertSql = 'SELECT DISTINCT UP.USER_ID AS USER_ID, ' +
                        'CONCAT(UP.FIRST_NAME, " ", UP.LAST_NAME) AS NAME, ' +
                        'UP.DESIGNATION AS DESIGNATION, ' +
                        'UP.PROFILE_PICTURE AS PROFILE_PICTURE, ' +
                        'UP.USER_STATUS AS STATUS, ' +
                        'IF(UP.user_id in (SELECT MI1.user_id FROM member_information MI1 ' +
                        'WHERE MI1.conversation_id = ?), 1, null) AS IS_ACTIVE ' +
                        'FROM user_profile UP ' +
                        'WHERE UP.user_id NOT IN (SELECT MI.USER_ID FROM member_information MI ' +
                        'WHERE MI.CONVERSATION_ID = ? AND MI.IS_ACTIVE = 1) ' +
                        'ORDER BY NAME';
                    val = [conversation_id, conversation_id];
                } else if (requestKey == 'deleteList') {
                    insertSql = 'SELECT DISTINCT UP.USER_ID AS USER_ID, ' +
                        'CONCAT(UP.FIRST_NAME, " ", UP.LAST_NAME) AS NAME, ' +
                        'UP.DESIGNATION AS DESIGNATION, ' +
                        'UP.PROFILE_PICTURE AS PROFILE_PICTURE, ' +
                        'UP.USER_STATUS AS STATUS, ' +
                        'IF(CI.owner = UP.user_id, 1, 0) AS IS_OWNER, ' +
                        'MI.admin AS IS_ADMIN, ' +
                        'IF(UP.user_id in (SELECT MI1.user_id FROM member_information MI1 ' +
                        'WHERE MI1.conversation_id = ?), 1, null) AS IS_ACTIVE ' +
                        'FROM user_profile UP, conversation_information CI, member_information MI ' +
                        'WHERE UP.user_id IN (SELECT MI.USER_ID FROM member_information MI ' +
                        'WHERE MI.CONVERSATION_ID = ? AND MI.IS_ACTIVE = 1) ' +
                        'AND CI.conversation_id = ? ' +
                        'AND MI.conversation_id = CI.conversation_id ' +
                        'AND MI.user_id = UP.user_id ' +
                        'ORDER BY NAME';
                    val = [conversation_id, conversation_id, conversation_id];
                } else if (requestKey == 'contactList') {
                    insertSql = 'SELECT DISTINCT CONCAT(UP.first_name, " " , UP.last_name) AS NAME, ' +
                        'UP.designation AS DESIGNATION, ' +
                        'UP.profile_picture AS PROFILE_PICTURE, ' +
                        'UP.user_status AS STATUS, ' +
                        'UP.user_id AS USER_ID ' +
                        'FROM user_profile UP ' +
                        'WHERE UP.user_id <> ? ' +
                        'ORDER BY NAME'
                    val = [conversation_id];
                }
                conn.query(insertSql, val,
                    function(err, rows, fields) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        var resContacts = [];
                        for (var contactIndex in rows) {
                            var contactsObj = rows[contactIndex];
                            resContacts.push(contactsObj);
                        }
                        res.json(resContacts);
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/conversations', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var host_id = query.host_id;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT DISTINCT CI.conversation_id AS CONVERSATION_ID, ' +
                    'IF(CI.is_group = 0, UP.PROFILE_PICTURE, CI.group_picture) AS PROFILE_PICTURE, ' +
                    'IF(CI.is_group = 0, CONCAT(UP.FIRST_NAME," ", UP.LAST_NAME), ' +
                    'CI.group_name) AS NAME, ' +
                    'T.TEXT_MESSAGE AS TEXT, ' +
                    'T.IS_MEDIA AS IS_MEDIA, ' +
                    'MI.admin AS IS_ADMIN, ' +
                    'IF(CI.owner = ?, 1, 0) AS IS_OWNER, ' +
                    'IF(CI.is_group = 0, UP.user_status, "Black") AS STATUS, ' +
                    'T.SEND_TIME AS SEND_TIME, ' +
                    'MI.favorite AS FAVORITE ' +
                    'FROM user_profile UP, text T, conversation_information CI, member_information MI, ' +
                    'member_information MI2, text_status TS ' +
                    'WHERE MI.USER_ID = ? ' +
                    'AND MI.CONVERSATION_ID = CI.CONVERSATION_ID ' +
                    'AND MI.CONVERSATION_ID = T.CONVERSATION_ID ' +
                    'AND MI.conversation_id = MI2.conversation_id ' +
                    'AND MI.user_id <> MI2.user_id ' +
                    'AND UP.user_id = MI2.user_id ' +
                    'AND UP.USER_ID <> ? ' +
                    'AND MI.is_active = 1 ' +
                    'AND TS.member_id = MI.member_id ' +
                    'AND TS.is_deleted <> 1 ' +
                    'GROUP BY T.conversation_id ' +
                    'ORDER BY FAVORITE DESC, SEND_TIME DESC, NAME;', [host_id, host_id, host_id],
                    function(err, rows, fields) {
                        if (err) {
                            console.log(query);
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        var resUser = [];
                        for (var userIndex in rows) {
                            var userObj = rows[userIndex];
                            resUser.push(userObj);
                        }
                        res.json(resUser);
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/getMoreMessages', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var conversation_id = query.conversation_id;
        var host_id = query.host_id;
        var text_id = query.text_id;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT DISTINCT IF(CI.is_group = 1, ' +
                    'CONCAT(UP.first_name," " , UP.last_name), "") AS NAME, ' +
                    'CI.conversation_id AS CONVERSATION_ID, ' +
                    'T.sender_id AS SENDER_ID, ' +
                    'T.text_id AS TEXT_ID, ' +
                    'MI.user_id AS USER_ID, ' +
                    'T.text_message AS TEXT_MESSAGE, ' +
                    'T.send_time AS SEND_TIME, ' +
                    'T.text_id AS TEXT_ID, ' +
                    'MI.favorite AS FAVORITE, ' +
                    'CI.is_group AS IS_GROUP ' +
                    'FROM user_profile UP, text T, ' +
                    'conversation_information CI, ' +
                    'member_information MI, ' +
                    'text_status TS ' +
                    'WHERE CI.conversation_id = ? ' +
                    'AND MI.member_id = T.sender_id ' +
                    'AND MI.conversation_id = CI.conversation_id ' +
                    'AND T.conversation_id = CI.conversation_id ' +
                    'AND TS.text_id = T.text_id ' +
                    'AND MI.member_id = TS.member_id ' +
                    'AND TS.is_deleted <> 1 ' +
                    'AND UP.user_id = MI.user_id ' +
                    'AND T.send_time < (SELECT T.send_time from text T WHERE T.text_id = ?) ' +
                    'ORDER BY SEND_TIME DESC LIMIT 10;', [conversation_id, text_id],
                    function(err, rows, fields) {
                        if (err) {
                            console.log(query);
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        var resUser = [];
                        for (var userIndex in rows) {
                            var userObj = rows[userIndex];
                            resUser.push(userObj);
                        }
                        res.json(resUser);
                        console.log(JSON.stringify(resUser));
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/getNewMessages', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var conversation_id = query.conversation_id;
        var host_id = query.host_id;
        var text_id = query.text_id;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT DISTINCT IF(CI.is_group = 1, ' +
                    'CONCAT(UP.first_name," " , UP.last_name), "") AS NAME, ' +
                    'CI.conversation_id AS CONVERSATION_ID, ' +
                    'T.sender_id AS SENDER_ID, ' +
                    'T.text_id AS TEXT_ID, ' +
                    'MI.user_id AS USER_ID, ' +
                    'T.text_message AS TEXT_MESSAGE, ' +
                    'T.send_time AS SEND_TIME, ' +
                    'T.text_id AS TEXT_ID, ' +
                    'MI.favorite AS FAVORITE, ' +
                    'CI.is_group AS IS_GROUP ' +
                    'FROM user_profile UP, text T, conversation_information CI, member_information MI, ' +
                    'text_status TS ' +
                    'WHERE CI.conversation_id = ? ' +
                    'AND MI.member_id = T.sender_id ' +
                    'AND MI.conversation_id = CI.conversation_id ' +
                    'AND T.conversation_id = CI.conversation_id ' +
                    'AND TS.text_id = T.text_id ' +
                    'AND MI.member_id = TS.member_id ' +
                    'AND TS.is_deleted <> 1 ' +
                    'AND UP.user_id = MI.user_id ' +
                    'AND T.send_time > (SELECT T.send_time from text T WHERE T.text_id = ?) ' +
                    'ORDER BY SEND_TIME DESC', [conversation_id, text_id],
                    function(err, rows, fields) {
                        if (err) {
                            console.log(query);
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        var resUser = [];
                        for (var userIndex in rows) {
                            var userObj = rows[userIndex];
                            resUser.push(userObj);
                        }
                        res.json(resUser);
                        console.log(JSON.stringify(resUser));
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/getMessageThread', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var conversation_id = query.conversation_id;
        var host_id = query.host_id;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT DISTINCT IF(CI.is_group = 1, ' +
                    'CONCAT(UP.first_name," " , UP.last_name), "") AS NAME, ' +
                    'CI.conversation_id AS CONVERSATION_ID, T.sender_id AS SENDER_ID, T.text_id AS TEXT_ID, ' +
                    'MI.user_id AS USER_ID, T.text_message AS TEXT_MESSAGE, T.send_time AS SEND_TIME, ' +
                    'T.text_id AS TEXT_ID, MI.favorite AS FAVORITE, CI.is_group AS IS_GROUP ' +
                    'FROM user_profile UP, text T, conversation_information CI, member_information MI, ' +
                    'text_status TS WHERE CI.conversation_id = ? ' +
                    'AND MI.member_id = T.sender_id ' +
                    'AND MI.conversation_id = CI.conversation_id ' +
                    'AND T.conversation_id = CI.conversation_id ' +
                    'AND TS.text_id = T.text_id ' +
                    'AND MI.member_id = TS.member_id ' +
                    'AND TS.is_deleted <> 1 ' +
                    'AND UP.user_id = MI.user_id ' +
                    'ORDER BY SEND_TIME DESC ' +
                    'LIMIT 10', [conversation_id],
                    function(err, rows, fields) {
                        if (err) {
                            console.log(query);
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        var resUser = [];
                        for (var userIndex in rows) {
                            var userObj = rows[userIndex];
                            resUser.push(userObj);
                        }
                        res.json(resUser);
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/getLastText', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var conversationId = query.conversationId;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('CALL get_last_text(?, @text)', [conversationId],
                    function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        console.log(result[0]);
                        res.json(result[0]);
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/findConversation', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var host_id = query.host_id;
        var user_id = query.user_id;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT DISTINCT MI1.conversation_id AS CONVERSATION_ID, ' +
                    'IF(MI1.user_id = ?, MI1.admin, MI2.admin) AS IS_ADMIN, ' +
                    'IF(CI.owner = ?, 1, 0) AS IS_OWNER ' +
                    'from member_information MI1, member_information MI2, conversation_information CI ' +
                    'where MI1.conversation_id = MI2.conversation_id and MI1.member_id <> MI2.member_id ' +
                    'and ((MI1.user_id = ? and MI2.user_id = ?) or (MI1.user_id = ? and MI2.user_id = ?)) ' +
                    'and CI.conversation_id = MI1.conversation_id ' +
                    'and CI.is_group = 0;', [host_id, host_id, host_id, user_id, user_id, host_id],
                    function(err, rows, fields) {
                        if (err) {
                            console.log(query);
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        var resUser = [];
                        for (var userIndex in rows) {
                            var userObj = rows[userIndex];
                            resUser.push(userObj);
                        }
                        res.json(resUser);
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/editConversationInformation', function(req, res, next) {
    try {
        var reqObj = req.body;
        var requestKey = reqObj.requestKey;
        var hostId = reqObj.hostId;
        var insertSql;
        var insertValues;
        console.log(reqObj);
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (requestKey == 'createConversation') {
                    var userId = reqObj.userId;
                    insertSql = "Call create_conversation(?,?, @conversationId)";
                    insertValues = [hostId, userId];
                } else if (requestKey == 'createGroup') {
                    var groupName = reqObj.groupName;
                    insertSql = "Call create_group(?,?, @conversationId)";
                    insertValues = [hostId, groupName];
                }
                var query = conn.query(insertSql, insertValues, function(err, result) {
                    if (err) {
                        console.error('SQL error: ', err);
                        return next(err);
                    }
                    res.json(result[0]);
                });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/editMemberInformation', function(req, res, next) {
    try {
        var reqObj = req.body;
        var userId = reqObj.userId;
        var conversationId = reqObj.conversationId;
        var requestKey = reqObj.requestKey;
        var insertSql;
        var val = [];

        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (requestKey == 'admin') {
                    insertSql = "CALL make_admin(?,?)";
                    var v = [userId, conversationId];
                    val.push(v);
                } else if (requestKey == 'favorite') {
                    insertSql = "CALL make_favorite(?,?)";
                    var v = [userId, conversationId];
                    val.push(v);
                } else if (requestKey == 'addMember') {
                    insertSql = "CALL add_member(?,?)";
                    for (var j = 0; j < userId.length; j++) {
                        var v = [userId[j], conversationId];
                        val.push(v);
                    }
                } else if (requestKey == 'removeMember') {
                    insertSql = "CALL remove_member(?,?)";
                    for (var j = 0; j < userId.length; j++) {
                        var v = [conversationId, userId[j]];
                        val.push(v);
                    }
                }
                for (var i = 0; i < val.length; i++) {
                    var query = conn.query(insertSql, val[i],
                        function(err, result) {
                            if (err) {
                                console.error('SQL error: ', err);
                                return next(err);
                            }
                            console.log(result);
                        });
                }
                res.json({ "success": "success" });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/editUserProfile', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var userId = query.userId;
        var status = query.status;
        var requestKey = query.requestKey;
        var insertSql;
        var val;

        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (requestKey == 'status') {
                    console.log("In Status");
                    insertSql = "CALL user_status(?,?)";
                    val = [userId, status];
                } else if (requestKey == 'lastActivity') {
                    console.log("In Last Activity");
                    insertSql = "CALL user_last_activity(?)";
                    val = [userId];
                }
                var query = conn.query(insertSql, val,
                    function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        console.log(result);
                        res.json({ "success": "success" });
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/editText', function(req, res, next) {
    try {
        var reqObj = req.body;
        var textId = reqObj.textId;
        var conversationId = reqObj.conversationId;
        var userId = reqObj.senderId;
        var textMessage = reqObj.textMessage;
        var stat = reqObj.stat;
        var requestKey = reqObj.requestKey;
        var insertSql;
        var val;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (requestKey == 'statMessage') {
                    console.log("In Stat Message");
                    insertSql = "CALL make_stat(?)";
                    val = [textId];
                } else if (requestKey == 'deteleText') {
                    insertSql = "CALL delete_text(?)";
                    val = [textId];
                } else if (requestKey == 'sendMessage') {
                    insertSql = "CALL send_message(?,?,?,?,  @textId)";
                    val = [conversationId, userId, textMessage, stat];
                    console.log('The passing values: ' + JSON.stringify(val));
                }
                var query = conn.query(insertSql, val,
                    function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        console.log(result[0]);
                        res.json(result[0]);
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/editTextStatus', function(req, res, next) {
    try {
        var reqObj = req.body;
        var userId = reqObj.userId;
        var textId = reqObj.textId;
        var conversationId = reqObj.conversationId;
        var requestKey = reqObj.requestKey;
        var insertSql;
        var val;

        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (requestKey == 'clearText') {
                    insertSql = "CALL clear_text(?,?)";
                    val = [textId, userId];
                } else if (requestKey == 'clearConversation') {
                    insertSql = "CALL clear_conversation(?,?)";
                    val = [conversationId, userId];
                } else if (requestKey == 'unclearText') {
                    insertSql = "CALL unclear_text(?,?)";
                    val = [conversationId, userId];
                }
                var query = conn.query(insertSql, val,
                    function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        console.log(result);
                        res.json({ "success": "success" });
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});