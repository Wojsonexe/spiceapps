'use client';

import { useParams, useRouter } from 'next/navigation';
import { useApplication } from '@/hooks/use-applications';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CopyButton } from '@/components/ui/copy-button';
import { ArrowLeft, Trash2 } from 'lucide-react';
import { format } from 'date-fns';

export default function ApplicationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { data: client, isLoading } = useApplication(id);

  if (isLoading) return (
    <div className="max-w-2xl space-y-4">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-64 w-full" />
    </div>
  );

  if (!client) return <p className="text-muted-foreground">Application not found.</p>;

  return (
    <div className="max-w-2xl space-y-6">
      <Button variant="ghost" size="sm" onClick={() => router.back()} className="-ml-2">
        <ArrowLeft className="mr-2 h-4 w-4" /> Back
      </Button>

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">{client.name}</h2>
          {client.description && (
            <p className="text-muted-foreground">{client.description}</p>
          )}
        </div>
        <Badge variant={client.isActive ? 'default' : 'secondary'}>
          {client.isActive ? 'Active' : 'Inactive'}
        </Badge>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="credentials">Credentials</TabsTrigger>
          <TabsTrigger value="danger">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 mt-4">
          <Card>
            <CardHeader><CardTitle className="text-sm">Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-sm">
              <Row label="Client Type" value={<Badge variant="outline">{client.clientType}</Badge>} />
              <Row label="Require Consent" value={client.requireConsent ? 'Yes' : 'No'} />
              <Row label="Require PKCE" value={client.requirePkce ? 'Yes' : 'No'} />
              <Row label="Created" value={format(new Date(client.createdAt), 'PPP')} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Redirect URIs</CardTitle></CardHeader>
            <CardContent>
              {client.redirectUris.length === 0 ? (
                <p className="text-sm text-muted-foreground">No redirect URIs configured</p>
              ) : (
                <ul className="space-y-1">
                  {client.redirectUris.map((uri) => (
                    <li key={uri} className="font-mono text-sm bg-muted rounded px-2 py-1 break-all">
                      {uri}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Allowed Scopes</CardTitle></CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {client.allowedScopes.map(scope => (
                  <Badge key={scope} variant="secondary">{scope}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="credentials" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Client Credentials</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <p className="text-sm text-muted-foreground">Client ID</p>
                <div className="flex gap-2 items-center">
                  <code className="flex-1 rounded bg-muted px-3 py-2 text-sm font-mono break-all">
                    {client.clientId}
                  </code>
                  <CopyButton value={client.clientId} />
                </div>
              </div>
              {client.clientType === 'Confidential' && (
                <p className="text-sm text-muted-foreground rounded-md border border-yellow-500/30 bg-yellow-500/5 px-3 py-2">
                  ⚠️ Client secret is not shown for security reasons. If you need a new secret, delete and re-register the application.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="danger" className="mt-4">
          <Card className="border-destructive/50">
            <CardHeader>
              <CardTitle className="text-sm text-destructive">Delete Application</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Permanently delete this application. All tokens issued to this client will be invalidated.
              </p>
              <Button
                variant="destructive"
                onClick={() => router.push(`/applications?delete=${client.clientId}`)}
                className="gap-2"
              >
                <Trash2 className="h-4 w-4" /> Delete Application
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between items-center gap-4">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}