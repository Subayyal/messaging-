var app = require('express')();
var url = require('url');
var server = require('http').Server(app);
var io = require('socket.io')(server);
var mysql = require('mysql');
var bodyParser = require('body-parser');
var cors = require('cors');
var connection = require('express-myconnection');
var session  = require('express-session');
var passportSocketIo = require("passport.socketio");
var MySqlStore = require('express-mysql-session')(session);
var cookieParser = require('cookie-parser');
var passport = require('passport');
var flash    = require('connect-flash');
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
    host: '127.0.0.1',
    port: 3306,
    user: 'root',
    password: 'root',
    database: 'session'
};
 
var sessionConnection = mysql.createConnection(options);

// required for passport
var sessionStore = new MySqlStore({}, sessionConnection);

app.use(cookieParser());
app.use(session({
    key: 'aprimacookie',
  store: sessionStore,  //tell express to store session info in the Mysql store
  secret: 'mysecret',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

io.use(passportSocketIo.authorize({ //configure socket.io
   key: 'aprimacookie',
   cookieParser: cookieParser,
   secret:      'mysecret',    // make sure it's the same than the one you gave to express
   store:       sessionStore,        
   success:     onAuthorizeSuccess,  // *optional* callback on success
   fail:        onAuthorizeFail     // *optional* callback on fail/error
}));

app.use(connection(mysql, {
    host: "127.0.0.1",
    user: "root",
    password: "root",
    database: "messaging"
}, 'request'));

server.listen(4041, function() {
  console.log('server up and running at 4041 port');
});

function onAuthorizeSuccess(data, accept){
  console.log('successful connection to socket.io');
  // If you use socket.io@1.X the callback looks different
  accept();
}

function onAuthorizeFail(data, message, error, accept){
  if(error) accept(new Error(message));
  console.log('failed connection to socket.io:', message);
  accept(null, false);

}
var socketList = new Array();
io.on('connection', function(socket){
    if(socket.request.user.logged_in == false)
        socket.disconnect();
    socketList.push(socket);
    console.log('socketList length: ' + socketList.length);

    socket.on('join-conversation', function(data){
        for(var i = 0; i < socketList.length; i++){
            if(socketList[i].request.user.user_id == data.userId){
                socket.join(data.group);
                console.log('user ' + data.userId + ' has joined group ' + data.group);
                break;
            }
        }
        io.of('/').in('1').clients(function(error, clients){
          if (error) throw error;
          console.log(clients);
        });
    });

    socket.on('new-message', function(data){
        console.log('new-message called');
        socket.to(data.threadId).emit('new-message-receive',{threadId: data.threadId, hostId: data.hostId});
    });

    socket.on('disconnect', function(){
        console.log('called');
        for(var i = 0; i < socketList.length; i++){
            if(socketList[i].id == socket.id){
                socketList.splice(i,1);
                break;
            }
        }
        socket.disconnect(true);
        console.log(socketList.length);
    });
});

app.post('/login', function(req, res, next) {
  passport.authenticate('local-login', function(err, user, info) {
    if (err) { return next(err); }
    // Redirect if it fails
    if (!user) { return res.json(user); }
    req.logIn(user, function(err) {
      if (err) { return next(err); }
      // Redirect if it succeeds
      console.log(user.user_id);
      return res.json(user.user_id);
      
    });
  })(req, res, next);
});

app.get('/logout', function(req, res){
    req.logout();
    req.session.destroy();
    res.json({'success': 'success'});
});

//======================================================================================//
//======================================================================================//

app.get('/user/getUserGuid', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        console.log(query);
        var received_id = query.received_id;
        console.log(received_id);
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT UP.USER_ID AS "UP_USER_ID" FROM user_profile UP ' +
                    'WHERE UP.USER_ID = ?', [received_id],
                    function(err, rows, fields) {
                        if (err) {
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

app.get('/getContacts', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        console.log(query);
        var conversation_id = query.conversationId;
        var toAdd = query.toAdd;
        var insertSql;
        var rec_obj;
        console.log(conversation_id);
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (toAdd == '1') {
                    insertSql = "SELECT DISTINCT UP.USER_ID AS USER_ID, " +
                        "CONCAT(UP.FIRST_NAME, ' ', UP.LAST_NAME) AS NAME, UP.DESIGNATION AS DESIGNATION, " +
                        "UP.PROFILE_PICTURE AS PROFILE_PICTURE, UP.USER_STATUS AS STATUS, " +
                        "IF(UP.user_id in (SELECT MI1.user_id FROM member_information MI1 " +
                        "WHERE MI1.conversation_id = ?), 1, null) AS IS_ACTIVE FROM user_profile UP " +
                        "WHERE UP.user_id not in (SELECT MI.USER_ID FROM member_information MI " +
                        "WHERE MI.CONVERSATION_ID = ? AND MI.IS_ACTIVE = 1) ORDER BY NAME";
                    rec_obj = [conversation_id, conversation_id];
                } else if (toAdd == '0') {
                    insertSql = "SELECT DISTINCT UP.USER_ID AS USER_ID, " +
                        "CONCAT(UP.FIRST_NAME, ' ', UP.LAST_NAME) AS NAME, UP.DESIGNATION AS DESIGNATION, " +
                        "UP.PROFILE_PICTURE AS PROFILE_PICTURE, UP.USER_STATUS AS STATUS, " +
                        "IF(UP.user_id in (SELECT MI1.user_id FROM member_information MI1 " +
                        "WHERE MI1.conversation_id = ?), 1, null) AS IS_ACTIVE FROM user_profile UP " +
                        "WHERE UP.user_id in (SELECT MI.USER_ID FROM member_information MI " +
                        "WHERE MI.CONVERSATION_ID = ? AND MI.IS_ACTIVE = 1) ORDER BY NAME";
                    rec_obj = [conversation_id, conversation_id];
                } else if (toAdd == '2') {
                    insertSql = 'SELECT DISTINCT CONCAT(UP.first_name, " " , UP.last_name) AS NAME, ' +
                        'UP.designation AS DESIGNATION, UP.profile_picture AS PROFILE_PICTURE, ' +
                        'UP.user_status AS STATUS, UP.user_id AS USER_ID FROM user_profile UP ' +
                        'WHERE UP.user_id <> ? ORDER BY NAME;'
                    rec_obj = conversation_id;
                }
                conn.query(insertSql, rec_obj,
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
    if(!req.isAuthenticated())

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
                    'IF(CI.is_group = 0, CONCAT(UP.FIRST_NAME," ", UP.LAST_NAME), CI.group_name) AS NAME, ' +
                    'T.TEXT_MESSAGE AS TEXT, T.IS_MEDIA AS IS_MEDIA, MI.admin AS ADMIN, ' +
                    'IF(CI.is_group = 0, UP.user_status, NULL) AS STATUS, T.SEND_TIME AS SEND_TIME ' +
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
                    'GROUP BY T.conversation_id ORDER BY SEND_TIME DESC, NAME;', [host_id, host_id],
                    function(err, rows, fields) {
                        if (err) {
                            //console.log(query);
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

app.get('/getMessageThread', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var conversation_id = query.conversation_id;
        var host_id = query.host_id
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT DISTINCT IF(CI.is_group = 1, ' +
                    'CONCAT(UP.first_name," " , UP.last_name), "") ' +
                    'AS NAME, CI.conversation_id AS CONVERSATION_ID, T.sender_id AS SENDER_ID, ' +
                    'T.text_id AS TEXT_ID, T.text_message AS TEXT_MESSAGE, T.send_time AS SEND_TIME, ' +
                    'CI.is_group AS IS_GROUP FROM user_profile UP, text T, conversation_information CI, ' +
                    'member_information MI, text_status TS WHERE T.conversation_id = ? ' +
                    'AND UP.user_id = T.sender_id AND T.conversation_id = CI.conversation_id ' +
                    'AND TS.text_id = T.text_id AND MI.user_id = ? AND MI.member_id = TS.member_id ' +
                    'AND TS.is_deleted <> 1 ORDER BY SEND_TIME;', [conversation_id, host_id],
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
                        //console.log(JSON.stringify(resUser));
                    });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/sendMessage', function(req, res, next) {
    try {
        var reqObj = req.body;
        var new_date = Date() + '';
        new_date = new_date.substr(1, 23);


        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                var insertSql = "INSERT INTO text SET ?";
                var insertValues = {
                    "text_id": ++i + new_date,
                    "conversation_id": reqObj.conversationId,
                    "sender_id": reqObj.senderId,
                    "text_message": reqObj.text,
                    "is_media": '0'
                };
                var query = conn.query(insertSql, insertValues, function(err, result) {
                    if (err) {
                        console.error('SQL error: ', err);
                        return next(err);
                    }
                    var text_id = insertValues.text_id;
                    res.json({ "text_id": text_id });
                });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/addMember', function(req, res, next) {
    try {
        var newDate = Date() + '';
        newDate = newDate.substr(1, 25);
        var query = url.parse(req.url, true).query;
        var conversation_id = query.conversationId;
        var user_id = query.userId;
        var is_active = query.isActive;
        var insertSql;
        var insertValues;

        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (is_active == 'null') {
                    console.log('In is_active = true');
                    insertSql = "INSERT INTO member_information SET ? ";
                    insertValues = {
                        "member_id": (++i + newDate),
                        "conversation_id": conversation_id,
                        "user_id": user_id,
                        "join_time": newDate,
                        "favorite": '0'
                    };

                } else {
                    console.log('In is_active = false');
                    insertSql = "UPDATE member_information MI SET MI.IS_ACTIVE = 1 " +
                        "WHERE MI.CONVERSATION_ID = ? AND MI.USER_ID = ?";
                    insertValues = [conversation_id, user_id];
                }
                var query = conn.query(insertSql, insertValues, function(err, result) {
                    if (err) {
                        console.error('SQL error: ', err);
                        return next(err);
                    }
                    var text_id = insertValues.text_id;
                    res.json({ "success": "success" });
                });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.get('/newConversation', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var host_id = query.host_id;
        var user_id = query.user_id;
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                conn.query('SELECT DISTINCT MI1.conversation_id AS CONVERSATION_ID, MI1.admin AS ADMIN ' +
                    'from member_information MI1, member_information MI2, conversation_information CI ' +
                    'where MI1.conversation_id = MI2.conversation_id and MI1.member_id <> MI2.member_id ' +
                    'and ((MI1.user_id = ? and MI2.user_id = ?) or (MI1.user_id = ? and MI2.user_id = ?)) ' +
                    'and CI.conversation_id = MI1.conversation_id ' +
                    'and CI.is_group = 0;', [host_id, user_id, user_id, host_id],
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

app.post('/createConversation', function(req, res, next) {
    try {

        var new_date = Date() + '';
        new_date = new_date.substr(1, 23);

        var conversation_id_new = ++i + new_date;
        var reqObj = req.body;
        console.log(reqObj);
        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                var insertSql = ["INSERT INTO conversation_information SET ?",
                    "INSERT INTO member_information SET ?", "INSERT INTO member_information SET ?"
                ];
                var insertValues = [{
                        "conversation_id": conversation_id_new,
                        "group_name": 'DEFAULT',
                        "conversation_created": new_date + '',
                        "owner": reqObj.hostId,
                        "group_picture": 'DEFAULT',
                        "is_group": '0',
                        "is_public": '0'
                    },
                    {
                        "member_id": (++i + new_date),
                        "conversation_id": conversation_id_new,
                        "user_id": reqObj.hostId,
                        "join_time": new_date,
                        "favorite": '0',
                        "is_active": '1',
                        "admin": '1'

                    },
                    {
                        "member_id": (++i + new_date),
                        "conversation_id": conversation_id_new,
                        "user_id": reqObj.userId,
                        "join_time": new_date,
                        "favorite": '0',
                        "is_active": '1',
                        "admin": '1'
                    }
                ];

                for (var j = 0; j < 3; j++) {

                    var query = conn.query(insertSql[j], insertValues[j], function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                    });
                }
                res.json({ "CONVERSATION_ID": conversation_id_new });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/removeMember', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var user_id = query.userId;
        var conversation_id = query.conversationId;

        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                var query = conn.query("UPDATE member_information MI SET MI.is_active = 0 " +
                    "WHERE MI.CONVERSATION_ID = ? AND MI.USER_ID = ?", [conversation_id, user_id],
                    function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        console.log(result);
                    });

                res.json({ "success": "success" });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});


app.post('/deleteConversation', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var host_id = query.hostId;
        var conversation_id = query.conversationId;
        var toDelete = query.toDelete;
        var insertSql;
        var val;


        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                if (toDelete == '1') {
                    console.log("In delete conversation");
                    insertSql = "CALL delete_conversation(?,?)";
                    val = [conversation_id, host_id];
                } else {
                    console.log("in get text back");
                    insertSql = "CALL get_text_back(?,?)";
                    val = [host_id, conversation_id];
                }

                var query = conn.query(insertSql, val,
                    function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        console.log(result);
                    });

                res.json({ "success": "success" });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

app.post('/deleteText', function(req, res, next) {
    try {
        var query = url.parse(req.url, true).query;
        var host_id = query.hostId;
        var text_id = query.textId;


        req.getConnection(function(err, conn) {
            if (err) {
                console.error('SQL Connection error: ', err);
                return next(err);
            } else {
                var query = conn.query("UPDATE text_status TS, member_information MI SET TS.is_deleted = 1 " +
                    "WHERE TS.member_id = MI.member_id AND TS.text_id = ? " +
                    "AND MI.user_id = ?", [text_id, host_id],
                    function(err, result) {
                        if (err) {
                            console.error('SQL error: ', err);
                            return next(err);
                        }
                        console.log(result);
                    });
                res.json({ "success": "success" });
            }
        });
    } catch (ex) {
        console.error("Internal error:" + ex);
        return next(ex);
    }
});

