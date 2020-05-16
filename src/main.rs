//! clank clank i wrote this code in a rush.
//! sorry!

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

const DEV_ROLE: RoleId = RoleId(545127775900532741);
const DEV_GUILD: GuildId = GuildId(544949171162185769);

enum Status{
    NeedPassword,
    NeedUsername
}

#[derive(Serialize, Deserialize)]
struct Store {
    creds: HashMap<UserId, UserCred>,
}

lazy_static!{
    static ref AUDIT: RwLock<File> = RwLock::new(
        OpenOptions::new().append(true).create(true)
        .open("auditlog.txt").expect("couldn't open audit log"));
}

impl Store{
    fn load() -> Self {
        File::open("ofsvn.json")
            .map_err(|_| ())
            .and_then(|file| serde_json::from_reader(file).map_err(|_| ()))
            .unwrap_or_else(|_| Store{creds: HashMap::new()})
    }
    fn save(&self){
        let temp = File::create("ofsvn.json").expect("couldn't open ofsvn.json");
        serde_json::to_writer(temp, self).expect("couldn't save store!");
        //TODO: Save to SVN cred file
        // please don't piggyback off of linux auth :pray:
    }
}

#[derive(Serialize, Deserialize)]
struct UserCred {
    username: String,
    password: String,
}

impl UserCred{
    fn new() -> Self{
        UserCred{
            username: "".to_owned(),
            password: "".to_owned(),
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
                // Create a UserCred
                let uc = UserCred::new();
                // Insert their new creds
                self.store.write().creds.insert(member.user_id(), uc);
                // Save the updated cred db
                //TODO: Maybe delay this
                self.store.read().save();
                let msg = format!("You've gained access to SVN. Use !password and !username to set your credentials.");
                println!("{} sent to {:?}", msg, member.user.read().name);
                //if let Err(why) = member.user.read().create_dm_channel(&ctx.http).map(|dm| dm.say(&ctx.http, &msg)) {
                //    println!("Error sending message: {:?}", why);
                //}
            },
            // lost access
            (false, true) => {
                //TODO: These should be members on Store
                self.store.write().creds.remove(&member.user_id());
                //TODO: Maybe delay this
                self.store.read().save();
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
                        writeln!(AUDIT.write(), "{} ({}) cleared credentials",
                            msg.author.id,
                            self.store.read().creds.get(&msg.author.id).unwrap().username
                        ).unwrap();
                        *self.store.write().creds.get_mut(&msg.author.id).unwrap() = UserCred::new();
                        self.store.read().save();
                        if let Err(why) = msg.channel_id.say(&ctx.http, "Username and Password Cleared.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }
                }else if msg.content == "!password adequite"{
                    if let Err(why) = msg.channel_id.say(&ctx.http, "Now listen here you little..") {
                        println!("Error sending message: {:?}", why);
                    }
                }else if msg.content.len() > 18 && msg.content.get(0..10) == Some("!password ") {
                    let access = self.investigate(&ctx, &member);
                    if !access{
                        if let Err(why) = msg.channel_id.say(&ctx.http, "you are not authorized.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }else{
                        writeln!(AUDIT.write(), "{} ({}) set password",
                            msg.author.id,
                            self.store.read().creds.get(&msg.author.id).unwrap().username
                        ).unwrap();
                        self.store.write().creds.get_mut(&msg.author.id).unwrap().password = msg.content.get(10..).unwrap().to_owned();
                        self.store.read().save();
                        if let Err(why) = msg.channel_id.say(&ctx.http, "Password Set.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }
                }else if msg.content.len() > 14 && msg.content.get(0..10) == Some("!username ") {
                    let access = self.investigate(&ctx, &member);
                    if !access{
                        if let Err(why) = msg.channel_id.say(&ctx.http, "you are not authorized.") {
                            println!("Error sending message: {:?}", why);
                        }
                    }else{
                        //TODO: this should really all be done in a method on Store.
                        let username = msg.content.get(10..).unwrap().to_owned();
                        if !username.chars().all(|c| c.is_alphanumeric() || c=='-') || self.store.read().creds.iter().any(|kv| kv.1.username==username) {
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Bad username. Alphanumeric and dashes only, must be unique") {
                                println!("Error sending message: {:?}", why);
                            }
                        }else{
                            writeln!(AUDIT.write(), "{} changed username from {} to {}",
                                msg.author.id,
                                self.store.read().creds.get(&msg.author.id).unwrap().username,
                                username
                            ).unwrap();
                            self.store.write().creds.get_mut(&msg.author.id).unwrap().username = username;
                            self.store.read().save();
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Username Set.") {
                                println!("Error sending message: {:?}", why);
                            }
                        }
                    }
                }else{
                    if let Err(why) = msg.channel_id.say(&ctx.http, "help: run !password password to set your SVN password. Password must be *adequite*.\nrun !username to set your SVN username.\nor !clear to clear your credentials") {
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
