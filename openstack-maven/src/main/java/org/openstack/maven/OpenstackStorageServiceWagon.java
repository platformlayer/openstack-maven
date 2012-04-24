/*
 * Copyright 2010 SpringSource
 * Copyright 2012 Justin Santa Barbara
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openstack.maven;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.proxy.ProxyInfoProvider;
import org.apache.maven.wagon.repository.Repository;
import org.openstack.client.OpenstackAuthenticationException;
import org.openstack.client.OpenstackCredentials;
import org.openstack.client.OpenstackException;
import org.openstack.client.OpenstackNotFoundException;
import org.openstack.client.common.OpenstackSession;
import org.openstack.client.storage.OpenstackStorageClient;
import org.openstack.model.storage.ObjectProperties;
import org.openstack.model.storage.StorageObject;
import org.openstack.utils.Io;

/**
 * An implementation of the Maven Wagon interface that allows you to access the OpenStack Storage service. URLs that
 * reference the OpenStack storage service should be in the form of <code>openstack://bucket.name</code>. As an example
 * <code>openstack://static.openstack.org</code> would put files into the <code>static.openstack.org</code> bucket on
 * the OpenStack Storage service.
 * <p/>
 * This implementation uses the <code>username</code> and <code>passphrase</code> portions of the server authentication
 * metadata for credentials.
 * 
 */
public final class OpenstackStorageServiceWagon extends AbstractWagon {

    private OpenstackStorageClient service;

    private String bucket;

    private String basedir;

    private String tenant;

    private String authUrl;

    public OpenstackStorageServiceWagon() {
        super(false);
    }

    @Override
    protected void connectToRepository(Repository source, AuthenticationInfo authenticationInfo, ProxyInfoProvider proxyInfoProvider)
        throws OpenstackException, AuthenticationException {
        try {
            // Jets3tProperties jets3tProperties = new Jets3tProperties();
            // if (proxyInfoProvider != null) {
            // ProxyInfo proxyInfo = proxyInfoProvider.getProxyInfo("http");
            // if (proxyInfo != null) {
            // jets3tProperties.setProperty("httpclient.proxy-autodetect", "false");
            // jets3tProperties.setProperty("httpclient.proxy-host", proxyInfo.getHost());
            // jets3tProperties.setProperty("httpclient.proxy-port", new Integer(proxyInfo.getPort()).toString());
            // }
            // }
            // new RestS3Service(getCredentials(authenticationInfo), "mavens3wagon", null, jets3tProperties);

            // String protocol = source.getProtocol();
            // if (Strings.isNullOrEmpty(protocol)) {
            // protocol = "https";
            // }
            // String portString = "";
            // int port = source.getPort();
            // if (port != WagonConstants.UNKNOWN_PORT) {
            // portString = ":" + port;
            // }
            //
            // String host = source.getHost();
            //
            // String authUrl = protocol + "://" + host + portString + "/v2.0";

            OpenstackSession session = OpenstackSession.create();
            OpenstackCredentials credentials = getCredentials(source, authenticationInfo);
            if (credentials == null) {
                throw new AuthenticationException("OpenStack storage credentials were not supplied");
            }
            session.authenticate(credentials);
            this.service = session.getStorageClient();
        } catch (OpenstackAuthenticationException e) {
            throw new AuthenticationException("Cannot authenticate with current credentials", e);
        }
        this.bucket = source.getHost();
        this.basedir = getBaseDir(source);
    }

    @Override
    protected boolean doesRemoteResourceExist(String resourceName) {
        try {
            this.service.getObjectDetails(this.bucket, this.basedir + resourceName);
        } catch (OpenstackNotFoundException e) {
            return false;
        }
        return true;
    }

    @Override
    protected void disconnectFromRepository() {
        // Nothing to do for OpenStack Storage
    }

    @Override
    protected void getResource(String resourceName, File destination, TransferProgress progress) throws ResourceDoesNotExistException, IOException {
        try {
            /* ObjectProperties metadata = */this.service.getObjectDetails(this.bucket, this.basedir + resourceName);
        } catch (OpenstackNotFoundException e) {
            throw new ResourceDoesNotExistException("Resource " + resourceName + " does not exist in the repository", e);
        }

        if (!destination.getParentFile().exists()) {
            destination.getParentFile().mkdirs();
        }

        InputStream in = null;
        OutputStream out = null;
        try {
            try {
                in = this.service.getDataInputStream(this.bucket, this.basedir + resourceName);
            } catch (OpenstackException se) {
                throw new IllegalStateException(se);
            }
            out = new TransferProgressFileOutputStream(destination, progress);
            byte[] buffer = new byte[1024];
            int length;
            while ((length = in.read(buffer)) != -1) {
                out.write(buffer, 0, length);
            }
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Nothing possible at this point
                }
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    // Nothing possible at this point
                }
            }
        }
    }

    @Override
    protected boolean isRemoteResourceNewer(String resourceName, long timestamp) {
        ObjectProperties object = this.service.getObjectDetails(this.bucket, this.basedir + resourceName);
        return object.getLastModifiedDate().compareTo(new Date(timestamp)) < 0;
    }

    @Override
    protected List<String> listDirectory(String directory) throws Exception {
        List<String> fileNames = new ArrayList<String>();
        for (StorageObject object : this.service.listObjects(this.bucket, this.basedir + directory, "")) {
            String key = this.bucket + "/" + this.basedir + directory + "/" + object.getName();
            fileNames.add(key);
        }
        return fileNames;
    }

    @Override
    protected void putResource(File source, String destination, TransferProgress progress) throws IOException, OpenstackException {
        buildDestinationPath(getDestinationPath(destination));
        // S3Object object = new S3Object(this.basedir + destination);
        // object.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ);
        // object.setDataInputFile(source);
        // object.setContentLength(source.length());

        InputStream in = null;
        try {
            InputStream objectData = new TransferProgressFileInputStream(source, progress);
            long contentLength = source.length();
            this.service.putObject(this.bucket, this.basedir + destination, objectData, contentLength);

            // This code was in the s3 wagon, but looks to be useless
            // in = new FileInputStream(source);
            // byte[] buffer = new byte[1024];
            // int length;
            // while ((length = in.read(buffer)) != -1) {
            // progress.notify(buffer, length);
            // }
        } finally {
            Io.safeClose(in);
        }
    }

    private void buildDestinationPath(String destination) throws OpenstackException, IOException {
        String objectPath = this.basedir + destination + "/";

        // S3Object object = new S3Object(objectPath);
        // object.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ);
        // object.setContentLength(0);
        ByteArrayInputStream emptyInputStream = new ByteArrayInputStream(new byte[0]);
        this.service.putObject(this.bucket, objectPath, emptyInputStream, 0);
        int index = destination.lastIndexOf('/');
        if (index != -1) {
            buildDestinationPath(destination.substring(0, index));
        }
    }

    private String getDestinationPath(String destination) {
        return destination.substring(0, destination.lastIndexOf('/'));
    }

    private String getBaseDir(Repository source) {
        StringBuilder sb = new StringBuilder(source.getBasedir());
        sb.deleteCharAt(0);
        if (sb.charAt(sb.length() - 1) != '/') {
            sb.append('/');
        }
        return sb.toString();
    }

    private OpenstackCredentials getCredentials(Repository source, AuthenticationInfo authenticationInfo) throws AuthenticationException {
        if (authenticationInfo == null) {
            return null;
        }

        // String authUrl = source.getUrl();
        if (this.authUrl == null) {
            throw new AuthenticationException("OpenStack Storage requires a authUrl to be set");
        }

        // String tenant = source.getParameter("tenant");
        // if (tenant == null) {
        // throw new AuthenticationException("OpenStack Storage requires a tenant to be set");
        // }

        String accessKey = authenticationInfo.getUserName();
        String secretKey = authenticationInfo.getPassword();
        if (accessKey == null || secretKey == null) {
            throw new AuthenticationException("OpenStack Storage requires a username and passphrase to be set");
        }
        return new OpenstackCredentials(this.authUrl, accessKey, secretKey, this.tenant);
    }

    public String getTenant() {
        return this.tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getAuthUrl() {
        return this.authUrl;
    }

    public void setAuthUrl(String authUrl) {
        this.authUrl = authUrl;
    }
}
