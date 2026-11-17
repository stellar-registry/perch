// use soroban_sdk::{Address, Env};

// pub trait HasAdmin {
//     fn admin(&self) -> &Address;
// }

// // #[contracttrait(DefaultAdmin)]
// pub trait Constructable<T: HasAdmin = Address>: crate::Administratable {
//     #[allow(unused_variables)]
//     fn construct(env: &Env, args: T) {}
//     fn constructor(env: &Env, args: T) {
//         Self::set_admin(env, args.admin());
//         Self::construct(env, args);
//     }
// }

// // // Generates
// #[macro_export]
// macro_rules! Constructable {
//     ($contract_name:ident) => {
//         impl Constructable<soroban_sdk::Address> for $contract_name {}
//         Constructable!($contract_name, $contract_name, soroban_sdk::Address);
//     };
//     ($contract_name:ident, $impl_name:path, $type_name:ty) => {
//         pub trait ConstructableExt {
//             type Args: HasAdmin;
//             fn __constructor(env: Env, args: Self::Args);
//         }
//         #[soroban_sdk::contractimpl]
//         impl ConstructableExt for $contract_name {
//             type Args = $type_name;
//             fn __constructor(env: Env, args: Self::Args) {
//                 <$impl_name as Constructable<$type_name>>::constructor(&env, args);
//             }
//         }
//     };
//     () => {};
// }

// // impl Constructable<Address> for DefaultAdmin {}

// impl HasAdmin for Address {
//     fn admin(&self) -> &Address {
//         self
//     }
// }

// // impl<T> HasAdmin for (Address, T) {
// //     fn admin(&self) -> &Address {
// //         &self.0
// //     }
// // }

// macro_rules! impl_has_admin_for_tuples {
//     ($($name:ident),*) => {
//         impl<$($name),*> HasAdmin for (Address, $($name),*) {
//             fn admin(&self) -> &Address { &self.0 }
//         }
//     };
// }
// impl_has_admin_for_tuples!();
// impl_has_admin_for_tuples!(T1);
// impl_has_admin_for_tuples!(T1, T2);
// impl_has_admin_for_tuples!(T1, T2, T3);
// impl_has_admin_for_tuples!(T1, T2, T3, T4);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7, T8);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
// impl_has_admin_for_tuples!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14);
// impl_has_admin_for_tuples!(
//     T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15
// );
