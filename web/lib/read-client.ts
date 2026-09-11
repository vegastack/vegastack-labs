"use client";

import { createReadClient } from "@/generated/read-api";

export const readClient = createReadClient((input, init) => fetch(input, init));
