const foundationChecks = [
  ["Go", "Compile-tested module"],
  ["Web", "Static export"],
  ["CI", "Credential-free checks"],
] as const;

export default function Home() {
  return (
    <main className="min-h-screen bg-background px-6 py-16 text-foreground sm:px-8">
      <section className="mx-auto flex max-w-3xl flex-col gap-8">
        <div className="flex flex-col gap-4">
          <p className="w-fit rounded-md border border-border bg-muted px-3 py-1 text-sm text-muted-foreground">
            Development scaffold
          </p>
          <h1 className="text-3xl font-medium">VegaStack Labs</h1>
          <p className="max-w-2xl text-base leading-7 text-muted-foreground">
            The public foundation is ready for verified implementation. This page does not expose
            an operator workflow or claim that the control plane exists yet.
          </p>
        </div>

        <dl className="grid gap-4 sm:grid-cols-3">
          {foundationChecks.map(([term, description]) => (
            <div key={term} className="rounded-lg border border-border bg-card p-4 text-card-foreground">
              <dt className="text-sm text-muted-foreground">{term}</dt>
              <dd className="mt-2 font-medium">{description}</dd>
            </div>
          ))}
        </dl>

        <p className="border-l-2 border-primary pl-4 text-sm leading-6 text-muted-foreground">
          Live infrastructure, provider access, private registry components, and releases remain
          separately gated.
        </p>
      </section>
    </main>
  );
}
