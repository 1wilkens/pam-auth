extern crate proc_macro;

use proc_macro::TokenStream;

use quote::quote;
use syn::{parse_macro_input, parse_quote};

#[proc_macro_attribute]
pub fn pam_enum(_: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as syn::Item);

    // Match only enums
    let mut def = match item {
        syn::Item::Enum(ie) => ie,
        _ => {
            // FIXME: slightly clunky
            return TokenStream::from(
                syn::Error::new_spanned(item, "[pam_enum] only works on enums").to_compile_error(),
            );
        }
    };

    // Clone original variants and create prefixed idents as they are used multiple times
    let variants: Vec<_> = def.variants.iter().cloned().collect();
    let idents: Vec<_> = def
        .variants
        .iter()
        .map(|v| prefix_ident(&v.ident, "PAM_"))
        .collect();

    // Attach additional derives to enum definition
    def.attrs.extend(derive_attrs());

    // Build enum variants from uppercased identifiers in pam_sys::
    def.variants = build_variants(&variants, &idents);

    // Build additional impl block for From<i32>
    let impl_block = build_impl_block(&def.ident, &variants, &idents);

    // Assemble the final TokenStream
    let output = quote! {
        #def
        #impl_block
    };

    output.into()
}

fn derive_attrs() -> Vec<syn::Attribute> {
    vec![
        parse_quote! { #[repr(C)] },
        parse_quote! { #[derive(Debug)] },
        parse_quote! { #[derive(Copy)] },
        parse_quote! { #[derive(Clone)] },
        parse_quote! { #[derive(PartialEq)] },
    ]
}

fn build_variants(
    variants: &[syn::Variant],
    idents: &[syn::Ident],
) -> syn::punctuated::Punctuated<syn::Variant, syn::token::Comma> {
    variants
        .iter()
        .zip(idents)
        .map(|(var, id)| {
            let mut var = var.clone();
            // Only insert our discriminant if none was provided
            if var.discriminant.is_none() {
                var.discriminant = Some((parse_quote!(=), parse_quote!(pam_sys::#id as isize)));
            }
            var
        })
        .collect()
}

fn build_impl_block(
    enum_name: &syn::Ident,
    variants: &[syn::Variant],
    idents: &[syn::Ident],
) -> syn::ItemImpl {
    let default = &variants[0].ident;

    let arms: Vec<syn::Arm> = variants
        .iter()
        .zip(idents)
        .map(|(var, id)| {
            let v_id = &var.ident;
            if let Some((_, ref expr)) = var.discriminant {
                // If we have an original expression for the variant, then use it..
                parse_quote!(#expr => #enum_name::#v_id,)
            } else {
                // otherwise, fallback to pam_sys
                // FIXME: This guard should not be necessary
                parse_quote!(x if x == pam_sys::#id.try_into().unwrap() => #enum_name::#v_id,)
            }
        })
        .collect();

    parse_quote! {
        impl std::convert::From<i32> for #enum_name {
            fn from(value: i32) -> Self {
                use ::std::convert::TryInto;

                match value {
                    #(#arms)*
                    _ => #enum_name::#default
                }
            }
        }
    }
}

fn prefix_ident(ident: &syn::Ident, prefix: &str) -> syn::Ident {
    syn::Ident::new(
        &format!("{}{}", prefix, ident.to_string().to_uppercase()),
        ident.span(),
    )
}
