using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace SI.Management.Web.Navigation;

/// <summary>
/// &lt;nav-ref page="/Admin/Departments/Index" /&gt; renders where a page sits in the menu -- "Configuration &gt; Departments
/// (setup)" -- from <see cref="NavModel"/>, as a link when the signed-in person sees that menu item and as plain text when
/// not. <c>then</c> adds a tab or section on that page; <c>link="false"</c> always renders text. A page text never spells a
/// menu path by hand, so it cannot drift from the menu.
/// </summary>
[HtmlTargetElement("nav-ref", TagStructure = TagStructure.WithoutEndTag)]
public sealed class NavRefTagHelper : TagHelper
{
    [HtmlAttributeName("page")] public string Page { get; set; } = "";
    [HtmlAttributeName("then")] public string? Then { get; set; }
    [HtmlAttributeName("link")] public bool Link { get; set; } = true;

    [ViewContext, HtmlAttributeNotBound] public ViewContext ViewContext { get; set; } = default!;

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        var item = NavModel.Find(Page) ?? throw new InvalidOperationException("<nav-ref page=\"" + Page + "\"> is not in the menu (Navigation/NavModel.cs)");
        // a tab of a menu item links to that tab (its own page), and needs both the item and the tab to be shown
        var tab = NavModel.TabOf(Page);
        var user = ViewContext?.HttpContext?.User;
        var visible = Link && user?.Identity?.IsAuthenticated == true
            && NavModel.Items.Where(i => i.Page == item.Page).Any(i => NavAccess.Of(user).Shown(i.Need))
            && (tab is null || NavAccess.Of(user!).Shown(tab.Need));
        output.TagMode = TagMode.StartTagAndEndTag;
        output.TagName = visible ? "a" : "span";
        output.Attributes.SetAttribute("class", "nav-ref");
        output.Attributes.SetAttribute("data-nav-ref", tab?.Page ?? item.Page);
        if (visible) output.Attributes.SetAttribute("href", tab?.Href ?? item.Href);
        output.Content.SetContent(NavModel.PathOf(tab?.Page ?? item.Page, Then));
    }
}
