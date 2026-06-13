import { NextRequest, NextResponse } from 'next/server';

const RPC_URL = 'https://sepolia-rollup.arbitrum.io/rpc';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    return NextResponse.json(json);
  } catch {
    return NextResponse.json({ error: { message: 'RPC proxy error' } }, { status: 502 });
  }
}
