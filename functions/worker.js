export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "FocusFlow Backend",
        status: "running"
      });
    }

    return Response.json(
      { error: "Not found" },
      { status: 404 }
    );
  }
};
