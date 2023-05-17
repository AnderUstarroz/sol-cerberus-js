# Development

To simplify development you can use the local version of the **sol-cerberus-js** in your webapp:

- Go to root folder of **/sol-cerberus-js**.
- Run `yarn link` to link the folder. You will get the following message:
  ```
  yarn link v1.22.17
  success Registered "sol-cerberus-js".
  info You can now run `yarn link "sol-cerberus-js"` in the projects where you want to use this package and it will be  used instead.
  ```
- Go to the root folder of the webapp using this library and run `yarn link "sol-cerberus-js"`
- You need to run `yarn build` any time you update the library in order to see the changes in the webapp.
- Note: If using VSCode hit `Comand + Shift + P` and type `Reload Window` to refresh typescript after running `yarn build`.
- Open the `package.json` of your webapp and add the corresponding local path of your `sol-cerberus-js` folder in your dependencies:
  ```
  "dependencies": {
    "sol-cerberus-js": "file:../sol-cerberus-js"
  }
  ```

To remove the link just run: `yarn unlink "sol-cerberus-js"`

# Publish Package

To publish the package:

- Run `yarn build`
- Run `yarn publish --access public`
- Type the new package version.
- Add the Google authentication code.
