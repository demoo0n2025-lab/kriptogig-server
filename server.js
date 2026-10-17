import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();

app.use(cors({
  origin: process.env.APP_ORIGIN
}));

app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

function verifyTelegramInitData(initData) {
  if (!initData || !process.env.BOT_TOKEN) {
    throw new Error("Нет данных Telegram или токена бота");
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash) {
    throw new Error("Нет подписи Telegram");
  }

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(process.env.BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  const received = Buffer.from(receivedHash, "hex");
  const calculated = Buffer.from(calculatedHash, "hex");

  if (
    received.length !== calculated.length ||
    !crypto.timingSafeEqual(received, calculated)
  ) {
    throw new Error("Подпись Telegram не прошла проверку");
  }

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);

  if (!authDate || now - authDate > 86400 || authDate > now + 60) {
    throw new Error("Данные авторизации устарели");
  }

  const userText = params.get("user");

  if (!userText) {
    throw new Error("Telegram не передал пользователя");
  }

  return JSON.parse(userText);
}

function requireTelegramUser(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";
    const initData = authorization.startsWith("tma ")
      ? authorization.slice(4)
      : "";

    req.telegramUser = verifyTelegramInitData(initData);
    next();
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
}

app.get("/api/me", requireTelegramUser, async (req, res) => {
  try {
    const user = req.telegramUser;
    const telegramId = String(user.id);

    const { error: insertError } = await supabase
      .from("profiles")
      .upsert(
        {
          telegram_id: telegramId,
          username: user.username || null
        },
        {
          onConflict: "telegram_id",
          ignoreDuplicates: true
        }
      );

    if (insertError) throw insertError;

    const { data, error } = await supabase
      .from("profiles")
      .select("telegram_id, username, balance, created_at")
      .eq("telegram_id", telegramId)
      .single();

    if (error) throw error;

    res.json({ profile: data });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Не удалось загрузить профиль" });
  }
});

app.get("/", (_req, res) => {
  res.send("kriptogig server is running");
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`Server started on port ${port}`);
});
