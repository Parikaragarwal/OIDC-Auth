import db from "../ultils/db.config.js";

export default async function logoutAllController(session_id){
    const user = await db.query.users.findFirst({
        where: {
            session_id: session_id,
        }
    });
    if(!user){
        throw new Error("Invalid session. User not found");
    }
    await db.users.update({
        where: {
            id: user.id,
        },
        set: {
            session_id: null,
        }
    });
    await db.query.userSessions.updateMany({
        where: {
            user_id: user.id,
        },
        set: {
            status: "revoked",
        }
    });
}