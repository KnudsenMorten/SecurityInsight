using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages;

/// <summary>
/// The page an unhandled error lands on (#284). It says WHAT failed (the page), WHY in plain words where that is known
/// (the database took too long, the database refused the read), WHAT TO DO, and the REFERENCE that finds the full error
/// in the application log -- the same reference is written on the log line, next to the exception type and the SQL error
/// number. Never the exception text itself: that is for the log, not the browser.
/// </summary>
[IgnoreAntiforgeryToken]
public sealed class ErrorModel(ILogger<ErrorModel> log) : PageModel
{
    public const string DefaultTitle = "Something went wrong";
    public const string DatabaseUnreachableTitle = "The database cannot be reached right now";

    public string Reference { get; private set; } = "";
    /// The page's heading: what happened, in a few words.
    public string Title { get; private set; } = DefaultTitle;
    public string? FailedPath { get; private set; }
    public string Why { get; private set; } = "The request could not be completed.";
    public string WhatToDo { get; private set; } = "Try again. If it keeps failing, give your administrator the reference below: the details are in the application log under it.";

    // no OnPost on purpose: a failed POST re-executes here as a POST, and a POST handler would count as a change (audit,
    // role matrix). The page describes itself when it renders, whatever the method.
    private bool _described;

    public void Describe()
    {
        if (_described) return;
        _described = true;
        Reference = ReferenceOf(HttpContext);
        var feature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
        FailedPath = feature?.Path;
        var ex = feature?.Error;
        if (ex is null) return;
        (Why, var todo) = Classify(ex);
        if (todo is not null) WhatToDo = todo;
        if (IsDatabaseUnreachable(ex)) Title = DatabaseUnreachableTitle;
        log.LogWarning("unhandled error on {Path}: {Type} {SqlNumber} (reference {Reference})", FailedPath, ex.GetType().FullName, Collection.CollectionPageModel.SqlNumber(ex), Reference);
    }

    /// The trace id of the request (what the log scopes carry), or the connection's request id.
    public static string ReferenceOf(HttpContext ctx) =>
        Activity.Current?.TraceId.ToString() is { Length: > 0 } t && t != "00000000000000000000000000000000" ? t : ctx.TraceIdentifier;

    /// SQL error numbers that say the database was never reached, or would not let the web app in: 40615 / 40914 / 47073
    /// (the server's firewall or network rules refused the connection), 18456 (the sign-in was refused), 4060 (the database
    /// cannot be opened), 40613 (the database is not available now), 53 / 10060 / 10061 / 11001 (the server was not found
    /// or did not answer).
    private static readonly HashSet<int> UnreachableNumbers = [40615, 40914, 47073, 18456, 4060, 40613, 53, 10060, 10061, 11001];

    /// <summary>
    /// PURE. Does a database error (its SQL error number and its text) say that the database could not be REACHED --
    /// as opposed to a query it ran and refused, or one that took too long? The one place every page's unhandled database
    /// error passes through (owner 2026-10-12: the first page after sign-in answered "Something went wrong" while the
    /// server's firewall refused the web app).
    /// </summary>
    public static bool IsDatabaseUnreachable(int? sqlNumber, string? message)
    {
        if (sqlNumber is { } n && UnreachableNumbers.Contains(n)) return true;
        var m = message ?? "";
        if (m.Length == 0 || sqlNumber is null) return false;
        return m.Contains("is not allowed to access the server", StringComparison.OrdinalIgnoreCase)
            || m.Contains("Cannot open server", StringComparison.OrdinalIgnoreCase)
            || m.Contains("Login failed for user", StringComparison.OrdinalIgnoreCase)
            || m.Contains("network-related or instance-specific error", StringComparison.OrdinalIgnoreCase)
            || m.Contains("Connection Timeout Expired", StringComparison.OrdinalIgnoreCase);
    }

    /// The same, for an exception: the first database error in its chain.
    public static bool IsDatabaseUnreachable(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
            if (e is Microsoft.Data.SqlClient.SqlException s) return IsDatabaseUnreachable(s.Number, s.Message);
        return false;
    }

    /// The plain-words reason and, where it differs from "try again", what to do.
    public static (string Why, string? WhatToDo) Classify(Exception ex)
    {
        // before the timeout: a connection that timed out is "cannot be reached", not "use a narrower view"
        if (IsDatabaseUnreachable(ex))
            return ("SecurityInsight cannot reach its database right now, so this page could not be shown. Nothing was changed.",
                    "This install's administrator should check the database server's firewall (Azure portal: the SQL server, Networking -- SecurityInsight's web app must be allowed through) and that the database is running. Then open the page again. The reference below finds the details in the application log.");
        if (ex is ViewTimeoutException || ViewTimeout.IsCommandTimeout(ex) || ex is TimeoutException)
            return ("The Pro database did not answer in time, so the page was stopped.",
                    "Open the page again with a narrower view (a filter, a search, fewer rows per page). If even a narrow view runs out of time, give your administrator the reference below.");
        if (Collection.CollectionPageModel.SqlNumber(ex) is not null)
            return ("The Pro database refused the request.", null);
        if (ex is OperationCanceledException)
            return ("The request was stopped before it finished.", null);
        return ("The request could not be completed.", null);
    }
}
