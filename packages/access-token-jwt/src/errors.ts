export class FetchError extends Error {
  constructor(
    public url: string,
    public statusCode?: number,
    public statusMessage?: string
  ) {
    super(`Failed to fetch ${url}, responded with ${statusCode}`);
    this.name = this.constructor.name;
  }
}

export class JsonParseError extends Error {
  constructor(public url: string) {
    super(`Failed to parse the response from ${url}`);
    this.name = this.constructor.name;
  }
}

export class AggregateError extends Error {
  constructor(public errors: Error[], message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}
