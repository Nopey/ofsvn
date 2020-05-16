use serenity::{
    model::{channel::Message, gateway::Ready, guild::Member},
    model::id::{GuildId, RoleId, UserId},
    prelude::*,
};

use serde_derive::*;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use lazy_static::*;
use std::process::Command;

const DEV_ROLE: RoleId = RoleId(545127775900532741);
const DEV_GUILD: GuildId = GuildId(544949171162185769);

const APACHE_PASSWD_FILE: &'static str = "/tmp/passwd.txt";
const AUDITLOG_FILE: &'static str = "auditlog.txt";
const BCRYPT_DIFFICULTY: &'static str = "8"; // 6 is default. 5-15 valid.

const HELP_STRING: &'static str = "help:
!username to set your SVN username. (do this first)
!password password to set your SVN password. Password must be *adequite*.
!clear to clear your credentials";

lazy_static!{
    static ref AUDIT: RwLock<File> = RwLock::new(
        OpenOptions::new().append(true).create(true)
        .open(AUDITLOG_FILE).expect("couldn't open audit log"));
}

#[derive(Serialize, Deserialize)]
struct Store {
    creds: HashMap<UserId, UserCred>,
}

impl Store{
    fn set_apache_password(name: &str, password: &str){
        println!("set apache password {:?}", Command::new("htpasswd")
        //            UwU
            .args(&["-BbC", BCRYPT_DIFFICULTY, APACHE_PASSWD_FILE, name, password])
            .output().unwrap());
    }
    fn delete_apache_user(name: &str){
        Command::new("htpasswd")
            .args(&["-D", APACHE_PASSWD_FILE, name])
            .output().unwrap();
    }
    fn load() -> Self {
        File::open("ofsvn.json")
            .map_err(|_| ())
            .and_then(|file| serde_json::from_reader(file).map_err(|_| ()))
            .unwrap_or_else(|_| Store{creds: HashMap::new()})
    }

    fn save(&self){
        let temp = File::create("ofsvn.json").expect("couldn't open ofsvn.json");
        serde_json::to_writer(temp, self).expect("couldn't save store!");
    }

    fn set_user_password(&mut self, user: UserId, password: &str) {
        let username = &self.creds.get(&user).unwrap().username;
        writeln!(AUDIT.write(), "{} ({:?}) set password",
            user,
            username
        ).unwrap();
        Self::set_apache_password(username, password);
    }

    fn set_user_username(&mut self, user: UserId, username: String) {
        let old_name = &self.creds.get(&user).unwrap().username;
        writeln!(AUDIT.write(), "{} changed username from {:?} to {:?}",
            user,
            old_name,
            username
        ).unwrap();
        Self::delete_apache_user(old_name);
        self.creds.get_mut(&user).unwrap().username = username;
        self.save();
    }

    fn clear_user(&mut self, user: UserId) {
        writeln!(AUDIT.write(), "{} ({:?}) cleared credentials",
            user,
            self.creds.get(&user).unwrap().username
        ).unwrap();
        *self.creds.get_mut(&user).unwrap() = UserCred::new();
        self.save();
    }

    fn add_user(&mut self, user: UserId) {
        // Create a UserCred
        let uc = UserCred::new();
        // Insert their new creds
        self.creds.insert(user, uc);
        // Save the updated cred db
        //TODO: Maybe delay this
        self.save();
    }

    fn remove_user(&mut self, user: UserId) {
        self.creds.remove(&user);
        //TODO: Maybe delay this
        self.save();
    }
}

#[derive(Serialize, Deserialize)]
struct UserCred {
    username: String,
}

impl UserCred{
    fn new() -> Self{
        UserCred{
            username: "".to_owned(),
        }
    }
}

struct Handler{
    store: RwLock<Store>,
}

impl Handler{
    fn investigate(&self, _ctx: &Context, member: &Member) -> bool {
        // no bots allowed
        if member.user.read().bot { return false };
        // check if they are allowed to write to the svn
        let access = member.roles.iter().any(|role| role.0==DEV_ROLE.0);
        // get previous status
        let had_access = self.store.read().creds.contains_key(&member.user_id());
        // user.create_dm_channel for sending creds
        match (access, had_access){
            // gained access
            (true, false) => {
                self.store.write().add_user(member.user_id());
                //TODO: re-enable welcome message
                // let msg = format!("You've gained access to SVN.\n{}", HELP_STRING);
                //if let Err(why) = member.user.read().create_dm_channel(&ctx.http).map(|dm| dm.say(&ctx.http, &msg)) {
                //    println!("Error sending message: {:?}", why);
                //}
                println!("welcome message sent to {:?}", member.user.read().name);
            },
            // lost access
            (false, true) => {
                //TODO: These should be members on Store
                self.store.write().remove_user(member.user_id());
                let msg = format!("You've lost access to SVN.");
                println!("{} sent to {:?}", msg, member.user.read().name);
                //if let Err(why) = member.user.read().create_dm_channel(&ctx.http).map(|dm| dm.say(&ctx.http, &msg)) {
                //    println!("Error sending message: {:?}", why);
                //}
            },
            (_, _) => ()
        }
        access
    }
}

fn try_parse<'a, 'b>(msg: &'a str, command: &'b str) -> Option<&'a str> {
    if msg.is_char_boundary(command.len()){
        Some(msg.split_at(command.len()))
    }else{
        None
    }.and_then(|(parsed_command, arg)|
        if parsed_command == command {
            Some(arg)
        }else{
            None
        }
    )
}

impl EventHandler for Handler {
    // for !password command, we handle DMs
    fn message(&self, ctx: Context, msg: Message) {
        if msg.is_private() && !msg.author.bot{
            if let Ok(member) = DEV_GUILD.member(&ctx.http, &msg.author){
                if msg.content == "!clear"{
                    let access = self.investigate(&ctx, &member);
                    if !access{
                        if let Err(why) = msg.channel_id.say(&ctx.http, "you are not authorized.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }else{
                        self.store.write().clear_user(msg.author.id);
                        if let Err(why) = msg.channel_id.say(&ctx.http, "Username and Password Cleared.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }
                }else if msg.content == "!password adequite"{
                    if let Err(why) = msg.channel_id.say(&ctx.http, "Now listen here you little..") {
                        println!("Error sending message: {:?}", why);
                    }
                }else if let Some(password) = try_parse(&msg.content, "!password ").or_else(|| try_parse(&msg.content, "!passwd ")) {
                    let access = self.investigate(&ctx, &member);
                    if !access{
                        if let Err(why) = msg.channel_id.say(&ctx.http, "you are not authorized.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }else{
                        if self.store.read().creds.get(&msg.author.id).unwrap().username == "" {
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Set your username first.") {
                                println!("Error sending message: {:?}", why);
                            }
                        }else if password.len() < 8 {
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Bad password. must be at least 8 chars.") {
                                println!("Error sending message: {:?}", why);
                            }
                        }else{
                            // SUCCESS
                            self.store.write().set_user_password(msg.author.id, password);
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Password Set. You should be able to login to svn now.") {
                                println!("Error sending message: {:?}", why);
                            }
                        }
                    }
                }else if let Some(username) = try_parse(&msg.content, "!username ").or_else(|| try_parse(&msg.content, "!name ")) {
                    let access = self.investigate(&ctx, &member);
                    if !access{
                        if let Err(why) = msg.channel_id.say(&ctx.http, "you are not authorized.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }else{
                        if username.len() < 5 || !username.chars().all(|c| c.is_alphanumeric() || c=='-') || self.store.read().creds.iter().any(|kv| kv.1.username==username) {
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Bad username. Alphanumeric and dashes only, must be unique, must be at least 5 chars.") {
                                println!("Error sending message: {:?}", why);
                            }
                        }else{
                            // SUCCESS
                            self.store.write().set_user_username(msg.author.id, username.to_owned());
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Username Set. (bonus: password cleared)") {
                                println!("Error sending message: {:?}", why);
                            }
                        }
                    }
                }else{
                    if let Err(why) = msg.channel_id.say(&ctx.http, HELP_STRING) {
                        println!("Error sending message: {:?}", why);
                    }
                }
            }
        }
    }

    // checks everybody in the server to make sure we're not lagging
    fn ready(&self, ctx: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
        for member in DEV_GUILD.members_iter(&ctx.http){
            let member = member.unwrap();
            self.investigate(&ctx, &member);
        }
        println!("init complete.");
    }

    fn guild_member_update(&self, ctx: Context, _old_if_available: Option<Member>, new: Member){
        self.investigate(&ctx, &new);
    }
}

fn main() {
    // Log in to Discord using a bot token from the environment
	let mut client = Client::new(&include_str!("discord_token.txt"), Handler{store: RwLock::new(Store::load())})
		.expect("login failed");

    if let Err(why) = client.start() {
        println!("Client error: {:?}", why);
    }
}
