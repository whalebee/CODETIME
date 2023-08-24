// UserStorage.js

"use strict";

class UserStorage{
   static users = { 
  // #: 다른 외부파일에서 내부 데이터에 접근하는게 불가하도록 하는 은닉화
        id: ["minjae","rkdalswo1021", "mj991021"],
        password: ["1234","12345","123456"],
        name: ["민재", "강민재", "강민재2"]
    };
 
  //은닉화된 데이터를 받아올 수 있도록 하는 메소드
	static getUsers(...fields) {
        const users = this.users;
        const newUsers = fields.reduce((newUsers, field) => {
            if (users.hasOwnProperty(field)){
                newUsers[field] = users[field];
            }
            return newUsers; 
        }, {});
        return newUsers;
    }

}

module.exports = UserStorage;
//in home.ctrl.js
const users = UseStorage.getUsers("id","password");