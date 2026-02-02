"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

type ApiResponse = {
  endpoint: string;
  status: number;
  duration: number;
  data: unknown;
  headers?: Record<string, string>;
};

export default function DemoPage() {
  const [memberId, setMemberId] = useState("100001");
  const [responses, setResponses] = useState<ApiResponse[]>([]);
  const [loading, setLoading] = useState<string | null>(null);

  async function fetchApi(endpoint: string) {
    setLoading(endpoint);
    const start = performance.now();

    try {
      const res = await fetch(endpoint, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });

      const duration = Math.round(performance.now() - start);
      const data = await res.json();

      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        if (key.toLowerCase().includes("ratelimit") || key.toLowerCase().includes("cache")) {
          headers[key] = value;
        }
      });

      setResponses((prev) => [{ endpoint, status: res.status, duration, data, headers }, ...prev.slice(0, 4)]);
    } catch (error) {
      const duration = Math.round(performance.now() - start);
      setResponses((prev) => [{ endpoint, status: 0, duration, data: { error: String(error) } }, ...prev.slice(0, 4)]);
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="container mx-auto max-w-6xl p-6 space-y-6">
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold">PRFC Connect - API Demo</h1>
        <p className="text-muted-foreground">
          Backend feature demonstration. Login at{" "}
          <a href="/dev/mock-portal" className="underline text-blue-600">
            /dev/mock-portal
          </a>{" "}
          first.
        </p>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* Member APIs */}
        <Card>
          <CardHeader>
            <CardTitle>Member API</CardTitle>
            <CardDescription>GET /api/members endpoints with rate limiting (10 req/min)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button onClick={() => fetchApi("/api/members")} disabled={loading === "/api/members"} className="w-full">
              {loading === "/api/members" ? "Loading..." : "Fetch All Members (389)"}
            </Button>

            <div className="flex gap-2">
              <Input
                value={memberId}
                onChange={(e) => setMemberId(e.target.value)}
                placeholder="Member ID"
                className="w-32"
              />
              <Button
                onClick={() => fetchApi(`/api/members/${memberId}`)}
                disabled={loading === `/api/members/${memberId}`}
                className="flex-1"
              >
                {loading === `/api/members/${memberId}` ? "Loading..." : "Fetch Member"}
              </Button>
            </div>

            <div className="text-xs text-muted-foreground">
              <p>• Returns 401 if not authenticated</p>
              <p>• Returns 429 if rate limited</p>
              <p>• IDs: 100001-100389 (admins: 100001, 100002)</p>
            </div>
          </CardContent>
        </Card>

        {/* Referral API */}
        <Card>
          <CardHeader>
            <CardTitle>Referral API</CardTitle>
            <CardDescription>GET /api/referral (admin only)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button onClick={() => fetchApi("/api/referral")} disabled={loading === "/api/referral"} className="w-full">
              {loading === "/api/referral" ? "Loading..." : "Fetch All Referrals"}
            </Button>

            <div className="text-xs text-muted-foreground">
              <p>• Requires admin session (100001 or 100002)</p>
              <p>• Returns 403 for non-admin users</p>
              <p>• Shows referral history from database</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Response Viewer */}
      <Card>
        <CardHeader>
          <CardTitle>API Responses</CardTitle>
          <CardDescription>Real-time response data (last 5 requests)</CardDescription>
        </CardHeader>
        <CardContent>
          {responses.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">Click a button above to make an API request</p>
          ) : (
            <div className="space-y-4">
              {responses.map((res, i) => (
                <div key={i} className="border rounded-lg p-4 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-sm font-mono">{res.endpoint}</code>
                    <Badge variant={res.status >= 200 && res.status < 300 ? "default" : "destructive"}>
                      {res.status}
                    </Badge>
                    <Badge variant="outline">{res.duration}ms</Badge>
                    {res.headers &&
                      Object.entries(res.headers).map(([k, v]) => (
                        <Badge key={k} variant="secondary" className="text-xs">
                          {k}: {v}
                        </Badge>
                      ))}
                  </div>
                  <pre className="bg-muted p-3 rounded text-xs overflow-auto max-h-48">
                    {JSON.stringify(res.data, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Architecture Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Architecture Summary</CardTitle>
          <CardDescription>What this demo showcases</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-3 gap-4 text-sm">
            <div>
              <h4 className="font-semibold mb-2">Security</h4>
              <ul className="space-y-1 text-muted-foreground">
                <li>• HMAC token validation</li>
                <li>• Rate limiting (Upstash)</li>
                <li>• DAL-based auth (not middleware)</li>
                <li>• CSRF protection</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Data Layer</h4>
              <ul className="space-y-1 text-muted-foreground">
                <li>• Prisma ORM (7 models)</li>
                <li>• Mock member data (Faker.js)</li>
                <li>• Environment-based switching</li>
                <li>• Zod validation</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Services</h4>
              <ul className="space-y-1 text-muted-foreground">
                <li>• Contact Groups (CRUD)</li>
                <li>• Email (Nodemailer + Resend)</li>
                <li>• Messages (email, SMS stub)</li>
                <li>• Referrals (batch + emails)</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
